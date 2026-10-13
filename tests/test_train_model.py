import importlib.util
import json
import sys
from pathlib import Path

import pytest

_PATH = Path(__file__).resolve().parents[1] / "scripts" / "train_model.py"
_spec = importlib.util.spec_from_file_location("train_model", _PATH)
train_model = importlib.util.module_from_spec(_spec)
sys.modules["train_model"] = train_model
_spec.loader.exec_module(train_model)

PHISH = ["Verify your account now or it will be suspended. Confirm your password.",
         "Your mailbox is full. Confirm your password at the link to keep receiving mail.",
         "Unusual sign-in detected. Verify your account details immediately."]
LEGIT = ["Minutes from the project meeting are attached.", "The library opens late on Friday.",
         "Photos from the weekend hike are in the shared album."]


def _message(body, year):
    return f"From: Someone <a@mail-host.example>\nSubject: Note\nDate: Mon, 06 Jan {year} 10:00:00 +0000\n\n{body}\n"


def _corpora(tmp_path):
    mbox = tmp_path / "phishing.mbox"
    mbox.write_text("".join(f"From sender@example Mon Jan  6 10:00:00 {year}\n{_message(body, year)}\n"
                            for year in (2020, 2021, 2024) for body in PHISH * 4))
    legit = tmp_path / "legit"
    legit.mkdir()
    for n, body in enumerate(LEGIT * 12):
        (legit / f"{n:05d}.msg").write_text(_message(body, 2002))
    (legit / "cmds").write_text("mv 00001 00002\n")  # corpus notes are skipped
    return mbox, legit


def test_training_writes_a_loadable_model_and_reports_a_time_split(tmp_path, capsys):
    mbox, legit = _corpora(tmp_path)
    out = tmp_path / "model.json"
    assert train_model.main(["--phishing", str(mbox), "--legitimate", str(legit), "--test-from-year", "2023",
                             "--out", str(out), "--epochs", "10"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["test"]["phishing"] == 12 and report["counts"]["test"] == 12 + 7
    assert report["test_by_legitimate_source"]["legit"]["messages"] == 7
    from phishlens.model import load_model
    assert 0.5 <= load_model(out).threshold < 1


def test_training_refuses_to_write_inside_the_repository(tmp_path, capsys):
    mbox, legit = _corpora(tmp_path)
    inside = Path(__file__).resolve().parents[1] / "model.json"
    assert train_model.main(["--phishing", str(mbox), "--legitimate", str(legit), "--test-from-year", "2023",
                             "--out", str(inside)]) == 1
    assert not inside.exists()
    assert "outside the repository" in capsys.readouterr().err


def test_training_needs_phishing_on_both_sides_of_the_split(tmp_path, capsys):
    mbox, legit = _corpora(tmp_path)
    assert train_model.main(["--phishing", str(mbox), "--legitimate", str(legit), "--test-from-year", "2030",
                             "--out", str(tmp_path / "m.json")]) == 1
    assert "leaves no phishing" in capsys.readouterr().err


def test_dev_scenarios_set_the_threshold_by_cross_fitting(tmp_path, capsys):
    mbox, legit = _corpora(tmp_path)
    assert train_model.main(["--phishing", str(mbox), "--legitimate", str(legit), "--test-from-year", "2023",
                             "--out", str(tmp_path / "m.json"), "--dev-scenarios", "2", "--epochs", "3"]) == 0
    report = json.loads(capsys.readouterr().out)
    oof = report["dev_out_of_fold"]
    assert oof["phishing"] + oof["legitimate"] == report["dev_scenarios"]["count"] > 0
