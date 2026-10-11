import json
import math

import pytest

from phishlens.analyzer import analyze
from phishlens.cli import main
from phishlens.message import parse_bytes
from phishlens.model import (DIMENSION, Model, ModelError, feature_index, load_model, message_text, save_model,
                             tokens, train, vectorize)

PHISH = ["Verify your account now or it will be suspended. Click the link to confirm your password.",
         "Your mailbox is full. Confirm your password at the link below to keep receiving mail.",
         "Unusual sign-in detected. Verify your account details immediately to avoid suspension."]
LEGIT = ["Minutes from Tuesday's project meeting are attached. Next meeting is Thursday.",
         "The library will open late on Friday. Thanks for your patience.",
         "Here are the photos from the weekend hike. See you at training."]


def _email(body, subject="Hello"):
    return parse_bytes(f"From: Someone <a@mail-host.example>\nSubject: {subject}\n\n{body}\n".encode())


def _toy_model(threshold=0.5):
    texts = PHISH * 5 + LEGIT * 5
    labels = [1] * 15 + [0] * 15
    bias, weights = train([vectorize(tokens(t)) for t in texts], labels, epochs=20)
    return Model(bias, weights, threshold, {"note": "toy"})


def test_tokens_cover_words_pairs_chinese_and_links():
    toks = tokens("Verify account at https://evil.example now. 请核实账户")
    assert "verify" in toks and "verify account" in toks
    assert "请核" in toks and "账户" in toks and "__link__" in toks
    assert not any("evil" in t for t in toks)  # URLs are not words


def test_vectors_are_unit_length_and_hashed_in_range():
    vector = vectorize(tokens("one two three"))
    assert math.isclose(sum(v * v for v in vector.values()), 1.0)
    assert all(0 <= i < DIMENSION for i in vector)
    assert vectorize([]) == {}


def test_training_separates_toy_examples_and_explains_with_message_words():
    model = _toy_model()
    phish_p, words = model.assess(_email("Please verify your account and confirm your password."))
    legit_p, _ = model.assess(_email("Notes from the project meeting are attached."))
    assert phish_p > 0.5 > legit_p
    assert words and all(w in tokens("please verify your account and confirm your password hello") for w in words)


def test_training_requires_both_classes():
    with pytest.raises(ValueError):
        train([{1: 1.0}], [1])


def test_model_round_trip_keeps_no_training_words(tmp_path):
    model = _toy_model()
    path = tmp_path / "model.json"
    save_model(path, model)
    text = path.read_text()
    assert "verify" not in text and "password" not in text
    loaded = load_model(path)
    vector = vectorize(tokens(PHISH[0]))
    assert math.isclose(loaded.probability(vector), model.probability(vector), abs_tol=1e-4)


@pytest.mark.parametrize("data, reason", [
    ({"format": "other"}, "not a PhishLens model"),
    ({"format": "phishlens-model", "version": 99}, "different PhishLens feature version"),
    ({"format": "phishlens-model", "version": 1, "features": "hashed-words-v1", "dimension": 1 << 18,
      "bias": 0, "threshold": 1.5, "weights": {}}, "threshold is invalid"),
    ({"format": "phishlens-model", "version": 1, "features": "hashed-words-v1", "dimension": 1 << 18,
      "bias": 0, "threshold": 0.8, "weights": {"-1": 0.1}}, "weights are invalid"),
    ({"format": "phishlens-model", "version": 1, "features": "hashed-words-v1", "dimension": 1 << 18,
      "bias": 0, "threshold": 0.8, "weights": {"5": float("nan")}}, "weights are invalid"),
])
def test_invalid_models_are_rejected(tmp_path, data, reason):
    path = tmp_path / "model.json"
    path.write_text(json.dumps(data))
    with pytest.raises(ModelError, match=reason):
        load_model(path)


def test_model_adds_one_finding_and_rules_are_unchanged():
    model = _toy_model()
    email = _email("Verify your account now or it will be suspended.")
    without = analyze(email)
    with_model = analyze(email, model=model)
    added = [f for f in with_model.findings if f.code.startswith("model.")]
    assert len(added) == 1 and added[0].code == "model.phishing_like" and added[0].severity == "high"
    assert [f.code for f in without.findings] == [f.code for f in with_model.findings if not f.code.startswith("model.")]
    calm = analyze(_email("Notes from the project meeting are attached."), model=model)
    assert [(f.code, f.severity) for f in calm.findings if f.code.startswith("model.")] == [("model.score", "info")]


def test_message_text_includes_visible_html():
    raw = (b"From: a@b.example\nSubject: Hi\nMIME-Version: 1.0\nContent-Type: text/html\n\n"
           b"<p>Confirm <b>password</b></p><script>ignored()</script>")
    assert "Confirm password" in message_text(parse_bytes(raw))


def test_cli_model_option(fixture_path, tmp_path, capsys):
    path = tmp_path / "model.json"
    save_model(path, _toy_model())
    assert main(["analyze", str(fixture_path("clean_newsletter.eml")), "--json", "--model", str(path)]) == 0
    codes = {f["code"] for f in json.loads(capsys.readouterr().out)["findings"]}
    assert codes & {"model.score", "model.phishing_like"}
    bad = tmp_path / "bad.json"
    bad.write_text("{}")
    assert main(["analyze", str(fixture_path("clean_newsletter.eml")), "--model", str(bad)]) == 1
    assert "invalid model" in capsys.readouterr().err
    assert main(["analyze", str(fixture_path("clean_newsletter.eml")), "--model", str(tmp_path / "no.json")]) == 1
    assert "cannot read model" in capsys.readouterr().err


def test_feature_index_is_stable():
    assert feature_index("verify") == feature_index("verify")
    assert feature_index("verify") != feature_index("verifx")
