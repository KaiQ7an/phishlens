"""Optional statistical model: logistic regression over hashed words.

The rules explain recognised warning signs. A model trained locally with
``scripts/train_model.py`` on public corpora can add a second opinion about
wording the rules do not cover. The model is a JSON file kept outside the
repository and loaded with ``--model``. Its weights are indexed by feature
hashes, so the file holds no words from the training mail; explanations list
words from the message being analysed. Everything here uses only the
standard library.
"""

from __future__ import annotations

import hashlib
import json
import math
import random
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from .message import ParsedEmail
from .urls import parse_html, strip_urls

FORMAT = "phishlens-model"
VERSION = 1
FEATURES = "hashed-words-v1"
DIMENSION = 1 << 18
MAX_MODEL_BYTES = 64 * 1024 * 1024
MAX_WORDS = 1500

_WORD_RE = re.compile(r"[a-z][a-z0-9']{1,24}")
_CJK_RE = re.compile(r"[一-鿿]{2,}")
_URL_HINT_RE = re.compile(r"https?://|www\.", re.IGNORECASE)


class ModelError(ValueError):
    """The model file is missing, too large or not a PhishLens model."""


def message_text(email: ParsedEmail) -> str:
    visible = parse_html(email.html)[1] if email.html else ""
    return "\n".join((email.subject, email.text, visible))


def tokens(text: str) -> list[str]:
    """Words, word pairs and Chinese character pairs, plus a link marker."""
    lowered = text.lower()
    words = _WORD_RE.findall(strip_urls(lowered))[:MAX_WORDS]
    result = words + [f"{a} {b}" for a, b in zip(words, words[1:])]
    pairs = 0
    for run in _CJK_RE.findall(lowered):
        for i in range(len(run) - 1):
            if pairs >= MAX_WORDS:
                break
            result.append(run[i:i + 2])
            pairs += 1
    if _URL_HINT_RE.search(text):
        result.append("__link__")
    return result


def feature_index(token: str) -> int:
    digest = hashlib.blake2b(token.encode("utf-8"), digest_size=8).digest()
    return int.from_bytes(digest, "big") % DIMENSION


def vectorize(toks: Iterable[str]) -> dict[int, float]:
    """Binary presence features, scaled to unit length."""
    indices = {feature_index(t) for t in toks}
    if not indices:
        return {}
    value = 1.0 / math.sqrt(len(indices))
    return dict.fromkeys(indices, value)


def _sigmoid(z: float) -> float:
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-z))
    e = math.exp(z)
    return e / (1.0 + e)


@dataclass(frozen=True)
class Model:
    bias: float
    weights: dict[int, float]
    threshold: float
    metadata: dict = field(default_factory=dict)

    def probability(self, vector: dict[int, float]) -> float:
        return _sigmoid(self.bias + sum(self.weights.get(i, 0.0) * v for i, v in vector.items()))

    def assess(self, email: ParsedEmail, top: int = 5) -> tuple[float, list[str]]:
        """Return the phishing probability and the message's most phishing-like words."""
        toks = tokens(message_text(email))
        vector = vectorize(toks)
        contributions: dict[str, float] = {}
        for token in toks:
            if token == "__link__" or token in contributions:
                continue
            contributions[token] = self.weights.get(feature_index(token), 0.0)
        strongest = sorted((t for t, w in contributions.items() if w > 0),
                           key=lambda t: contributions[t], reverse=True)[:top]
        return self.probability(vector), strongest


def train(vectors: Sequence[dict[int, float]], labels: Sequence[int], *, epochs: int = 8,
          learning_rate: float = 0.5, l2: float = 1e-5, seed: int = 0) -> tuple[float, dict[int, float]]:
    """Fit logistic regression with stochastic gradient descent.

    Classes are weighted inversely to their frequency, so an unbalanced corpus
    does not simply teach the majority label.
    """
    if len(vectors) != len(labels) or not vectors:
        raise ValueError("need the same, non-zero number of vectors and labels")
    positives = sum(labels)
    negatives = len(labels) - positives
    if not positives or not negatives:
        raise ValueError("training needs both phishing and legitimate examples")
    class_weight = {1: len(labels) / (2 * positives), 0: len(labels) / (2 * negatives)}
    weights: dict[int, float] = {}
    bias = 0.0
    order = list(range(len(vectors)))
    rng = random.Random(seed)
    for epoch in range(epochs):
        rng.shuffle(order)
        rate = learning_rate / (1 + epoch)
        for n in order:
            x, y = vectors[n], labels[n]
            p = _sigmoid(bias + sum(weights.get(i, 0.0) * v for i, v in x.items()))
            gradient = (p - y) * class_weight[y]
            for i, v in x.items():
                w = weights.get(i, 0.0)
                weights[i] = w - rate * (gradient * v + l2 * w)
            bias -= rate * gradient
    return bias, {i: w for i, w in weights.items() if abs(w) >= 1e-6}


def save_model(path: str | Path, model: Model) -> None:
    data = {
        "format": FORMAT, "version": VERSION, "features": FEATURES, "dimension": DIMENSION,
        "bias": round(model.bias, 6), "threshold": round(model.threshold, 6), "metadata": model.metadata,
        "weights": {str(i): round(w, 6) for i, w in sorted(model.weights.items())},
    }
    Path(path).write_text(json.dumps(data, separators=(",", ":")), encoding="utf-8")


def _finite(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def load_model(path: str | Path) -> Model:
    with open(path, "rb") as handle:
        raw = handle.read(MAX_MODEL_BYTES + 1)
    if len(raw) > MAX_MODEL_BYTES:
        raise ModelError(f"file is larger than {MAX_MODEL_BYTES // (1024 * 1024)} MiB")
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ModelError(f"not valid UTF-8 JSON ({error})") from error
    if not isinstance(data, dict) or data.get("format") != FORMAT:
        raise ModelError("not a PhishLens model file")
    if data.get("version") != VERSION or data.get("features") != FEATURES or data.get("dimension") != DIMENSION:
        raise ModelError("model was made for a different PhishLens feature version; retrain it")
    bias, threshold, raw_weights = data.get("bias"), data.get("threshold"), data.get("weights")
    if not _finite(bias) or not _finite(threshold) or not 0 < threshold < 1:
        raise ModelError("model bias or threshold is invalid")
    if not isinstance(raw_weights, dict):
        raise ModelError("model weights are missing")
    weights: dict[int, float] = {}
    for key, value in raw_weights.items():
        if not (isinstance(key, str) and key.isdigit() and int(key) < DIMENSION and _finite(value)):
            raise ModelError("model weights are invalid")
        weights[int(key)] = float(value)
    metadata = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
    return Model(float(bias), weights, float(threshold), metadata)
