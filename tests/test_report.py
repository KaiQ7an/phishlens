import json

from phishlens.analyzer import Report, analyze
from phishlens.auth import AuthVerdicts
from phishlens.display import terminal_text
from phishlens.message import Address, Attachment, ParsedEmail, parse_bytes
from phishlens.report import to_json, to_text
from phishlens.scoring import Finding
from phishlens.urls import Link


def test_control_characters_in_all_report_fields_are_escaped():
    attack = "\x1b[2J\r\nForged verdict\x08\x7f\x9b\u202e\u2028\ud800"
    email = ParsedEmail(subject=attack, sender=Address(attack, "a@example.org"),
                        parsing_warnings=[attack],
                        attachments=[Attachment(attack, attack, 1, "a" * 64)])
    report = Report(source=attack, email=email,
                    auth=AuthVerdicts("pass", "pass", "pass", attack, warnings=(attack,)),
                    findings=[Finding("test", "low", attack, attack)],
                    links=[Link("https://example.org/" + attack, attack)])
    rendered = to_text(report)
    for character in ("\x1b", "\r", "\x08", "\x7f", "\x9b", "\u202e", "\u2028", "\ud800"):
        assert character not in rendered
    assert "\\x1b[2J\\x0d\\x0aForged verdict" in rendered
    assert not any(line.startswith("Forged verdict") for line in rendered.splitlines())


def test_json_escapes_invisible_controls_but_retains_original_data():
    subject = "正常标题\x1b\u202e\u2028\ud800\U000e0061"
    report = Report("", ParsedEmail(subject=subject), None, [])
    encoded = to_json(report)
    assert "正常标题" in encoded
    for character in ("\x1b", "\u202e", "\u2028", "\ud800", "\U000e0061"):
        assert character not in encoded
    assert json.loads(encoded)["subject"] == subject
    encoded.encode("utf-8")


def test_readable_chinese_text_is_preserved():
    assert terminal_text("紧急通知：您的账户") == "紧急通知：您的账户"


def test_recorded_authentication_is_explicitly_unverified():
    raw = (b"Authentication-Results: mx.receiver.example; spf=pass; dkim=pass; dmarc=pass\n"
           b"From: test@example.org\n\nhello")
    report = analyze(parse_bytes(raw))
    assert "recorded, unverified" in to_text(report)
    assert json.loads(to_json(report))["authentication"]["verified"] is False


def test_conflicting_authentication_results_are_visible():
    raw = (b"Authentication-Results: mx.receiver.example; spf=pass; dkim=pass; dkim=fail; dmarc=pass\n"
           b"From: test@example.org\n\nhello")
    report = analyze(parse_bytes(raw))
    assert "Authentication warnings" in to_text(report)
    assert "No usable DKIM pass/fail result was recorded" in to_text(report)
    auth = json.loads(to_json(report))["authentication"]
    assert auth["dkim"] is None and auth["warnings"]


def test_container_hash_provenance_is_shown():
    email = ParsedEmail(attachments=[Attachment("forward.eml", "message/rfc822", 3, "a" * 64,
                                                hash_basis="serialized-mime")])
    report = Report("", email, None, [])
    assert "may differ from original attachment bytes" in to_text(report)
    assert json.loads(to_json(report))["attachments"][0]["hash_basis"] == "serialized-mime"
