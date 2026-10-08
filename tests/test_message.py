import hashlib
import os
from email.message import EmailMessage
from types import SimpleNamespace

import pytest

from phishlens.message import (DEFAULT_MAX_BYTES, MAX_MIME_DEPTH, MAX_MIME_PARTS,
                              EmailInputError, parse_bytes, parse_file)


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


def test_size_limit_accepts_exact_boundary_and_rejects_one_extra_byte(tmp_path):
    raw = b"Subject: hi\n\nbody\n"
    path = tmp_path / "message.eml"
    path.write_bytes(raw)
    assert parse_bytes(raw, max_bytes=len(raw)).text.strip() == "body"
    assert parse_file(path, max_bytes=len(raw)).text.strip() == "body"
    with pytest.raises(EmailInputError, match="size limit"):
        parse_bytes(raw, max_bytes=len(raw) - 1)
    with pytest.raises(EmailInputError, match="size limit"):
        parse_file(path, max_bytes=len(raw) - 1)


def test_default_size_limit_rejects_large_sparse_file(tmp_path):
    path = tmp_path / "large.eml"
    with path.open("wb") as stream:
        stream.truncate(DEFAULT_MAX_BYTES + 1)
    with pytest.raises(EmailInputError, match="size limit"):
        parse_file(path)


def test_file_growth_after_size_check_is_still_bounded(tmp_path, monkeypatch):
    raw = b"Subject: hi\n\nbody\n"
    path = tmp_path / "growing.eml"
    path.write_bytes(raw)
    original_fstat = os.fstat

    def stale_size(descriptor):
        metadata = original_fstat(descriptor)
        return SimpleNamespace(st_mode=metadata.st_mode, st_size=1)

    monkeypatch.setattr(os, "fstat", stale_size)
    assert parse_file(path, max_bytes=len(raw)).text.strip() == "body"
    with pytest.raises(EmailInputError, match="size limit"):
        parse_file(path, max_bytes=len(raw) - 1)


@pytest.mark.parametrize("raw", [b"", b" \r\n\t"])
def test_empty_email_is_rejected(raw):
    with pytest.raises(EmailInputError, match="empty"):
        parse_bytes(raw)


@pytest.mark.parametrize("limit", [0, -1])
def test_nonpositive_size_limit_is_rejected(limit, tmp_path):
    with pytest.raises(ValueError, match="positive integer"):
        parse_bytes(b"Subject: hi\n\nbody", max_bytes=limit)
    with pytest.raises(ValueError, match="positive integer"):
        parse_file(tmp_path / "not-read.eml", max_bytes=limit)


def test_unknown_charset_retains_text_with_warning():
    raw = (b"From: test@example.org\nContent-Type: text/plain; charset=made-up-charset\n\n"
           + "Urgent: 保证金".encode())
    email = parse_bytes(raw)
    assert "Urgent: 保证金" in email.text
    assert any("made-up-charset" in warning for warning in email.parsing_warnings)


def test_invalid_utf8_is_replaced_with_warning():
    email = parse_bytes(b"Content-Type: text/plain; charset=utf-8\n\nhello \xff world")
    assert email.text == "hello \ufffd world"
    assert any("replacement" in warning for warning in email.parsing_warnings)


def test_invalid_base64_padding_is_reported_after_decoding():
    email = parse_bytes(b"Content-Type: text/plain\nContent-Transfer-Encoding: base64\n\nYQ\n")
    assert email.text == "a"
    assert any("invalid padding" in warning for warning in email.parsing_warnings)


def test_missing_multipart_boundary_is_reported():
    email = parse_bytes(b"Content-Type: multipart/mixed; boundary=test\n\nbody without a boundary\n")
    assert any("start boundary" in warning for warning in email.parsing_warnings)


def test_truncated_multipart_retains_available_text_and_reports_warning():
    email = parse_bytes(b"Content-Type: multipart/mixed; boundary=test\n\n"
                        b"--test\nContent-Type: text/plain\n\nUrgent: wire transfer\n")
    assert "wire transfer" in email.text
    assert any("truncated" in warning for warning in email.parsing_warnings)


@pytest.mark.parametrize("depth", [MAX_MIME_DEPTH, MAX_MIME_DEPTH + 1])
def test_mime_nesting_limit(depth):
    leaf = EmailMessage()
    leaf.set_content("hello")
    for _ in range(depth):
        parent = EmailMessage()
        parent.make_mixed()
        parent.attach(leaf)
        leaf = parent
    raw = leaf.as_bytes()
    if depth == MAX_MIME_DEPTH:
        assert parse_bytes(raw).text.strip() == "hello"
    else:
        with pytest.raises(EmailInputError, match="nesting limit"):
            parse_bytes(raw)


def test_excessive_mime_parts_are_rejected():
    raw = (b"Content-Type: multipart/mixed; boundary=test\n\n"
           + b"--test\nContent-Type: text/plain\n\nhello\n" * MAX_MIME_PARTS
           + b"--test--\n")
    with pytest.raises(EmailInputError, match="part limit"):
        parse_bytes(raw)


def test_extreme_nesting_returns_input_error_instead_of_recursion_error():
    depth = 1200
    raw = b"".join(f"Content-Type: multipart/mixed; boundary=b{i}\n\n--b{i}\n".encode()
                   for i in range(depth))
    raw += b"Content-Type: text/plain\n\nhello\n"
    raw += b"".join(f"--b{i}--\n".encode() for i in reversed(range(depth)))
    with pytest.raises(EmailInputError, match="nested|nesting"):
        parse_bytes(raw)
