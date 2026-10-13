"""Train PhishLens's optional statistical model on local corpora.

Corpora and the trained model stay outside this repository: real messages
must never be committed, and the script refuses to write a model inside it.
Each source is an mbox file or a directory of raw message files.

    python -I scripts/train_model.py \\
        --phishing ~/Datasets/phishlens/nazario/phishing-20* \\
        --legitimate ~/Datasets/phishlens/spamassassin/extracted/*_ham* \\
        --test-from-year 2023 --out ~/Datasets/phishlens/model.json

Phishing messages dated in or after --test-from-year form the test set, so
the model is tested on mail newer than anything it learned from. Legitimate
messages are split at random (20% test), because public legitimate corpora
rarely span the same years. A further 10% of the training messages choose the
threshold: the lowest score that keeps legitimate validation messages below
the target false-alarm rate.

Public legitimate corpora are old mailing-list traffic, unlike today's
notices, receipts and alerts, so a model trained on them alone mostly learns
"old list mail versus modern mail". --dev-scenarios N adds the synthetic dev
split from tests/scenarios.py, repeated N times. The threshold then comes from
dev scenarios scored by models that did not see them (two-fold
cross-fitting). Holdout scenarios are never used.
"""

from __future__ import annotations

import argparse
import json
import mailbox
import random
import re
import sys
from datetime import date
from email.utils import parsedate_to_datetime
from pathlib import Path

from phishlens.message import EmailInputError, parse_bytes
from phishlens.model import Model, save_model, tokens, message_text, train, vectorize

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tests"))
MAX_MESSAGE_BYTES = 5 * 1024 * 1024
_HEADER_START_RE = re.compile(rb"^(?:From |[!-9;-~]+:)")


def _raw_messages(source: Path):
    if source.is_dir():
        for path in sorted(source.iterdir()):
            if path.is_file() and path.stat().st_size <= MAX_MESSAGE_BYTES:
                raw = path.read_bytes()
                if _HEADER_START_RE.match(raw.lstrip()):  # skip notes such as a corpus's 'cmds' file
                    yield raw
    else:
        box = mailbox.mbox(source, create=False)
        try:
            for key in box.keys():
                raw = box.get_bytes(key)
                if len(raw) <= MAX_MESSAGE_BYTES:
                    yield raw
        finally:
            box.close()


def load(sources: list[Path], label: int) -> list[tuple[dict[int, float], int, int | None]]:
    """Return (vector, label, year) for every message that parses."""
    examples = []
    skipped = 0
    for source in sources:
        for raw in _raw_messages(source):
            try:
                email = parse_bytes(raw, max_bytes=MAX_MESSAGE_BYTES)
            except EmailInputError:
                skipped += 1
                continue
            vector = vectorize(tokens(message_text(email)))
            if not vector:
                skipped += 1
                continue
            year = None
            try:
                year = parsedate_to_datetime(email.date).year if email.date else None
            except (TypeError, ValueError, IndexError):
                pass
            examples.append((vector, label, year))
    print(f"  {'phishing' if label else 'legitimate'}: {len(examples)} messages, {skipped} skipped",
          file=sys.stderr)
    return examples


def _dev_examples(seed: int) -> list[tuple[dict[int, float], int, None]]:
    from scenarios import SCENARIOS  # synthetic, labelled; only the dev split is used
    examples = [(vectorize(tokens(message_text(parse_bytes(s.raw)))), int(s.label == "phishing"), None)
                for s in SCENARIOS if s.split == "dev"]
    random.Random(seed).shuffle(examples)
    return examples


def _threshold(legit_scores: list[float], rate: float) -> float:
    scores = sorted(legit_scores)
    if not scores:
        return 0.5
    allowed = int(len(scores) * rate)
    return min(max(scores[-(allowed + 1)] + 1e-6, 0.5), 0.999)


def _rates(model: Model, examples) -> dict:
    tp = fn = fp = tn = 0
    for vector, label, _ in examples:
        flagged = model.probability(vector) >= model.threshold
        tp += flagged and label == 1
        fn += (not flagged) and label == 1
        fp += flagged and label == 0
        tn += (not flagged) and label == 0
    return {"phishing": tp + fn, "legitimate": fp + tn, "detected": tp, "false_alarms": fp,
            "recall": round(tp / (tp + fn), 3) if tp + fn else None,
            "false_alarm_rate": round(fp / (fp + tn), 3) if fp + tn else None}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--phishing", nargs="+", type=Path, required=True, metavar="SOURCE")
    parser.add_argument("--legitimate", nargs="+", type=Path, required=True, metavar="SOURCE")
    parser.add_argument("--out", type=Path, required=True, help="model file to write (outside this repository)")
    parser.add_argument("--test-from-year", type=int, required=True)
    parser.add_argument("--target-false-alarm-rate", type=float, default=0.05,
                        help="share of legitimate threshold-setting messages allowed above the threshold")
    parser.add_argument("--dev-scenarios", type=int, default=0, metavar="N",
                        help="add the synthetic dev scenarios N times (holdouts are never used)")
    parser.add_argument("--epochs", type=int, default=8)
    parser.add_argument("--seed", type=int, default=0)
    args = parser.parse_args(argv)

    out = args.out.expanduser().resolve()
    if out.is_relative_to(REPO):
        print("train_model: write the model outside the repository; it is derived from real mail",
              file=sys.stderr)
        return 1

    print("Reading corpora", file=sys.stderr)
    phishing = load([p.expanduser() for p in args.phishing], 1)
    rng = random.Random(args.seed)
    # Split each legitimate source on its own, so every source (for example
    # your own exported mailbox) has test messages and its own false-alarm rate.
    legit_test: list = []
    legit_pool: list = []
    held_by_source: dict[str, list] = {}
    for n, source in enumerate(args.legitimate):
        examples = load([source.expanduser()], 0)
        rng.shuffle(examples)
        cut = len(examples) // 5
        name = source.name if source.name not in held_by_source else f"{source.name} ({n + 1})"
        held_by_source[name] = examples[:cut]
        legit_test += examples[:cut]
        legit_pool += examples[cut:]
    test = [e for e in phishing if e[2] is not None and e[2] >= args.test_from_year] + legit_test
    pool = [e for e in phishing if e[2] is None or e[2] < args.test_from_year] + legit_pool
    rng.shuffle(pool)
    validation, training = pool[:len(pool) // 10], pool[len(pool) // 10:]
    if not any(e[1] for e in test) or not any(e[1] for e in training):
        print("train_model: --test-from-year leaves no phishing messages for training or testing",
              file=sys.stderr)
        return 1

    def fit(extra):
        examples = training + extra * args.dev_scenarios
        return train([e[0] for e in examples], [e[1] for e in examples], epochs=args.epochs, seed=args.seed)

    dev = _dev_examples(args.seed) if args.dev_scenarios > 0 else []
    dev_scores: list[tuple[float, int]] = []
    if dev:
        halves = (dev[::2], dev[1::2])
        for held, seen in (halves, halves[::-1]):
            print(f"Cross-fitting on {len(training)} messages and {len(seen)} dev scenarios", file=sys.stderr)
            fold = Model(*fit(seen), 0.5)
            dev_scores += [(fold.probability(e[0]), e[1]) for e in held]
    print(f"Training on {len(training)} messages and {len(dev)} dev scenarios", file=sys.stderr)
    bias, weights = fit(dev)
    if dev:
        threshold = _threshold([p for p, label in dev_scores if label == 0], args.target_false_alarm_rate)
    else:
        draft = Model(bias, weights, 0.5)
        threshold = _threshold([draft.probability(e[0]) for e in validation if e[1] == 0],
                               args.target_false_alarm_rate)

    metadata = {
        "trained": date.today().isoformat(),
        "phishing_sources": [p.name for p in args.phishing],
        "legitimate_sources": [p.name for p in args.legitimate],
        "test_from_year": args.test_from_year,
        "target_false_alarm_rate": args.target_false_alarm_rate,
        "dev_scenarios": {"copies": args.dev_scenarios, "count": len(dev)},
        "counts": {"training": len(training), "validation": len(validation), "test": len(test)},
    }
    model = Model(bias, weights, threshold, metadata)
    metadata["validation"] = _rates(model, validation)
    metadata["test"] = _rates(model, test)
    metadata["test_by_legitimate_source"] = {
        name: {"messages": len(held), "false_alarms": sum(model.probability(e[0]) >= threshold for e in held)}
        for name, held in held_by_source.items()}
    if dev_scores:
        flagged = [(p >= threshold, label) for p, label in dev_scores]
        metadata["dev_out_of_fold"] = {
            "phishing": sum(label for _, label in flagged), "legitimate": sum(1 - label for _, label in flagged),
            "detected": sum(f and label for f, label in flagged),
            "false_alarms": sum(f and not label for f, label in flagged)}
    save_model(out, model)
    print(json.dumps(metadata, indent=2))
    print(f"Wrote {out} ({len(weights)} weights, threshold {threshold:.3f})", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
