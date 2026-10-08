import hashlib

from phishlens.message import parse_bytes, parse_file


def test_parses_headers_and_bodies(fixture_path):
    email = parse_file(fixture_path("anchor_mismatch.eml"))
    assert email.subject == "Your enrolment has been updated"
    assert email.sender.address == "noreply@campus-notice.example"
    assert email.sender.domain == "campus-notice.example"
    assert "Review it at https://my.monash.edu/login" in email.text
    assert '<a href="http://203.0.113.45/monash/login.php">' in email.html


def test_decodes_chinese_display_name_and_subject(fixture_path):
    email = parse_file(fixture_path("zh_fake_police.eml"))
    assert email.sender.display_name == "中国驻墨尔本总领事馆"
    assert email.subject.startswith("【紧急通知】")
    assert "保证金" in email.text


def test_attachments_are_hashed_not_opened(fixture_path):
    email = parse_file(fixture_path("suspicious_attachment.eml"))
    names = [a.filename for a in email.attachments]
    assert names == ["Invoice_2026-10.pdf.exe", "remittance.html"]
    exe = email.attachments[0]
    expected = b"PhishLens test fixture. This is plain text, not a program.\n"
    assert exe.size == len(expected)
    assert exe.sha256 == hashlib.sha256(expected).hexdigest()


def test_reply_to_and_return_path(fixture_path):
    email = parse_file(fixture_path("dmarc_spoof.eml"))
    assert [r.address for r in email.reply_to] == ["reset-desk@helpdesk-mail.example"]
    assert email.return_path == "bounce@bulk-sender.example"


def test_missing_from_header():
    email = parse_bytes(b"Subject: hi\n\nbody\n")
    assert email.sender is None
    assert email.text.strip() == "body"
