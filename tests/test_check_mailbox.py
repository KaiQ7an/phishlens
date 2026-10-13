import importlib.util
import sys
from pathlib import Path

from phishlens.model import Model, save_model

_PATH = Path(__file__).resolve().parents[1] / "scripts" / "check_mailbox.py"
_spec = importlib.util.spec_from_file_location("check_mailbox", _PATH)
check_mailbox = importlib.util.module_from_spec(_spec)
sys.modules["check_mailbox"] = check_mailbox
_spec.loader.exec_module(check_mailbox)

SECRET_SUBJECT = "Dinner with Priya at Lygon St"
SECRET_ADDRESS = "priya.private@mail-host.example"


def _write_mail(tmp_path):
    inbox = tmp_path / "Inbox"
    (inbox / "nested").mkdir(parents=True)
    (inbox / "dinner-with-priya.eml").write_text(
        f"From: Priya <{SECRET_ADDRESS}>\nSubject: {SECRET_SUBJECT}\n\nSee you at 7 at https://maps.example/x\n")
    (inbox / "nested" / "alert.eml").write_text(
        "From: Security <alert@account-check.example>\nSubject: Verify now\n\n"
        "Your account will be suspended. Confirm your password and pay the $2.40 fee within 24 hours.\n")
    (inbox / "notes.txt").write_text("not an email")
    box = tmp_path / "Archive.mbox"
    box.write_text(f"From someone Mon Jan  6 10:00:00 2026\nFrom: Priya <{SECRET_ADDRESS}>\n"
                   f"Subject: {SECRET_SUBJECT}\n\nThanks for coming!\n\n")
    return inbox, box


def test_counts_without_revealing_messages(tmp_path):
    inbox, box = _write_mail(tmp_path)
    out = check_mailbox.check([inbox, box], "legitimate", None)
    assert "3 messages read as legitimate, 0 could not be read" in out
    assert "False alarms (suspicious or high): 1/3" in out
    assert "content.credentials" in out
    for private in (SECRET_SUBJECT, SECRET_ADDRESS, "Priya", "maps.example", "dinner-with-priya", "Verify now"):
        assert private not in out


def test_phishing_label_reports_detection_and_model_spread(tmp_path):
    inbox, _ = _write_mail(tmp_path)
    model_path = tmp_path / "model.json"
    save_model(model_path, Model(0.0, {}, 0.6))
    out = check_mailbox.main([str(inbox), "--label", "phishing", "--model", str(model_path)])
    assert out == 0


def test_model_line_and_unreadable_files(tmp_path, capsys):
    inbox, _ = _write_mail(tmp_path)
    (inbox / "empty.eml").write_text("")
    out = check_mailbox.check([inbox], "phishing", Model(0.0, {}, 0.6))
    assert "Detected (suspicious or high): 1/2" in out and "1 could not be read" in out
    assert "0/2 above threshold" in out
