import hashlib
import os
from email.message import EmailMessage
from types import SimpleNamespace

import pytest

from phishlens.message import (DEFAULT_MAX_BYTES, MAX_MIME_DEPTH, MAX_MIME_PARTS, Address,
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
    assert exe.hash_basis == "decoded-payload"


def test_inline_executable_is_an_attachment():
    message = EmailMessage()
    message.set_content("Outer message body")
    payload = b"Synthetic attachment; not an executable."
    message.add_attachment(payload, maintype="application", subtype="octet-stream",
                           filename="invoice.pdf.exe", disposition="inline")

    email = parse_bytes(message.as_bytes())

    assert email.text.strip() == "Outer message body"
    assert len(email.attachments) == 1
    attachment = email.attachments[0]
    assert attachment.filename == "invoice.pdf.exe"
    assert attachment.size == len(payload)
    assert attachment.sha256 == hashlib.sha256(payload).hexdigest()
    assert attachment.hash_basis == "decoded-payload"


def test_benign_inline_image_keeps_normal_text_and_html_bodies():
    message = EmailMessage()
    message.set_content("Plain body")
    message["Content-Disposition"] = "inline"
    message.add_alternative("<p>HTML body</p>", subtype="html", disposition="inline")
    payload = b"Synthetic image bytes"
    message.add_attachment(payload, maintype="image", subtype="png",
                           filename="logo.png", disposition="inline")

    email = parse_bytes(message.as_bytes())

    assert email.text.strip() == "Plain body"
    assert email.html.strip() == "<p>HTML body</p>"
    assert [attachment.filename for attachment in email.attachments] == ["logo.png"]
    assert email.attachments[0].sha256 == hashlib.sha256(payload).hexdigest()


@pytest.mark.parametrize("subtype", ["plain", "html"])
def test_named_inline_text_is_excluded_from_outer_body(subtype):
    message = EmailMessage()
    message.set_content("Outer message body")
    message.add_attachment("Attached text contains urgent demands", subtype=subtype,
                           filename="note.txt", disposition="inline")

    email = parse_bytes(message.as_bytes())

    assert email.text.strip() == "Outer message body"
    assert email.html == ""
    assert [attachment.filename for attachment in email.attachments] == ["note.txt"]


@pytest.mark.parametrize("filename,disposition", [("forwarded.eml", "attachment"),
                                                  (None, "inline")])
def test_encapsulated_message_is_opaque_to_outer_analysis(filename, disposition):
    forwarded = EmailMessage()
    forwarded["Subject"] = "Attached message"
    forwarded.set_content("Inner body: urgently wire funds")
    forwarded.add_alternative("<p>Inner HTML body</p>", subtype="html")
    forwarded.add_attachment(b"Synthetic attachment", maintype="application",
                             subtype="octet-stream", filename="inner.exe")
    message = EmailMessage()
    message.set_content("Outer message body")
    message.add_attachment(forwarded, filename=filename, disposition=disposition)

    email = parse_bytes(message.as_bytes())

    assert email.text.strip() == "Outer message body"
    assert email.html == ""
    assert len(email.attachments) == 1
    attachment = email.attachments[0]
    assert attachment.filename == (filename or "(unnamed)")
    assert attachment.content_type == "message/rfc822"
    assert attachment.size > 0
    assert len(attachment.sha256) == 64
    assert attachment.hash_basis == "serialized-mime"
    assert any("original attachment bytes" in warning for warning in email.parsing_warnings)


def test_attached_multipart_container_is_hashed_once_and_excludes_its_children():
    container = EmailMessage()
    container.set_content("Attached plain body")
    container.add_alternative("<p>Attached HTML body</p>", subtype="html")
    container["Content-Disposition"] = 'inline; filename="bundle.mime"'
    message = EmailMessage()
    message.set_content("Outer message body")
    message.make_mixed()
    message.attach(container)
    raw = message.as_bytes()
    serialized = container.as_bytes()

    email = parse_bytes(raw)

    assert email.text.strip() == "Outer message body"
    assert email.html == ""
    assert len(email.attachments) == 1
    attachment = email.attachments[0]
    assert attachment.filename == "bundle.mime"
    assert attachment.content_type == "multipart/alternative"
    assert attachment.size == len(serialized)
    assert attachment.sha256 == hashlib.sha256(serialized).hexdigest()
    assert attachment.hash_basis == "serialized-mime"


def test_malformed_encapsulated_multipart_retains_warnings_without_crashing():
    raw = (b"Content-Type: multipart/mixed; boundary=outer\n\n"
           b"--outer\nContent-Type: text/plain\n\nOuter body\n"
           b"--outer\nContent-Type: message/rfc822\n"
           b"Content-Disposition: attachment; filename=forwarded.eml\n\n"
           b"Content-Type: multipart/mixed; boundary=missing\n\n"
           b"No nested boundary here \xff\n"
           b"--outer--\n")

    email = parse_bytes(raw)

    assert email.text.strip() == "Outer body"
    assert len(email.attachments) == 1
    assert email.attachments[0].size > 0
    assert email.attachments[0].hash_basis == "serialized-mime"
    assert any("replacement characters" in warning for warning in email.parsing_warnings)
    assert any("start boundary" in warning for warning in email.parsing_warnings)


def test_reply_to_and_return_path(fixture_path):
    email = parse_file(fixture_path("dmarc_spoof.eml"))
    assert [r.address for r in email.reply_to] == ["reset-desk@helpdesk-mail.example"]
    assert email.return_path == "bounce@bulk-sender.example"


def test_missing_from_header():
    email = parse_bytes(b"Subject: hi\n\nbody\n")
    assert email.sender is None
    assert email.text.strip() == "body"


@pytest.mark.parametrize("name", ["From", "Reply-To"])
def test_recoverable_identity_header_defects_warn_without_dropping_content(name):
    raw = (f"{name}: bad local@shared1.ccsend.com\n\nSynthetic body\n").encode()

    email = parse_bytes(raw)

    address = email.sender if name == "From" else email.reply_to[0]
    assert address is not None
    assert address.domain == "shared1.ccsend.com"
    assert email.text.strip() == "Synthetic body"
    assert email.parsing_warnings == [
        f"{name} header contains parsing defects; the recovered address may be incomplete.",
    ]
    assert all("bad local" not in warning and "ccsend.com" not in warning
               for warning in email.parsing_warnings)


@pytest.mark.parametrize("name", ["From", "Reply-To"])
def test_duplicate_identity_headers_warn_and_preserve_first_address(name):
    raw = (f"{name}: first@example.org\n{name.lower()}: second@example.net\n\n"
           "Synthetic body\n").encode()

    email = parse_bytes(raw)

    address = email.sender if name == "From" else email.reply_to[0]
    assert address is not None
    assert address.address == "first@example.org"
    assert email.text.strip() == "Synthetic body"
    assert email.parsing_warnings == [
        f"Duplicate {name} headers were detected; the recovered identity may be ambiguous.",
    ]


@pytest.mark.parametrize("name", ["From", "Reply-To"])
def test_defects_in_unused_duplicate_identity_headers_are_reported(name):
    raw = (f"{name}: first@example.org\n{name}: bad local@shared1.ccsend.com\n\n"
           "Synthetic body\n").encode()

    email = parse_bytes(raw)

    address = email.sender if name == "From" else email.reply_to[0]
    assert address is not None
    assert address.address == "first@example.org"
    assert len(email.parsing_warnings) == 2
    assert any(f"Duplicate {name} headers" in warning for warning in email.parsing_warnings)
    assert any(f"{name} header contains parsing defects" in warning
               for warning in email.parsing_warnings)


def test_valid_quoted_identity_names_and_comments_have_no_parsing_warnings():
    raw = (b'From: "Newsletter, Weekly" (Updates) <newsletter@shared1.ccsend.com>\n'
           b'Reply-To: "Reply, Desk" <reply@example.org>, Support (Team) <support@example.org>\n'
           b'\nSynthetic body\n')

    email = parse_bytes(raw)

    assert email.sender == Address("Newsletter, Weekly", "newsletter@shared1.ccsend.com")
    assert email.reply_to == [Address("Reply, Desk", "reply@example.org"),
                              Address("Support", "support@example.org")]
    assert email.parsing_warnings == []


@pytest.mark.parametrize("address", ["broken", "@example.org", "sender@"])
def test_incomplete_mailbox_does_not_claim_a_sender_domain(address):
    assert Address("", address).domain == ""


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
@pytest.mark.parametrize("attached", [False, True])
def test_mime_nesting_limit(depth, attached):
    leaf = EmailMessage()
    leaf.set_content("hello")
    for _ in range(depth):
        parent = EmailMessage()
        parent.make_mixed()
        parent.attach(leaf)
        leaf = parent
    if attached:
        leaf["Content-Disposition"] = 'attachment; filename="nested.mime"'
    raw = leaf.as_bytes()
    if depth == MAX_MIME_DEPTH:
        email = parse_bytes(raw)
        assert email.text.strip() == ("" if attached else "hello")
        assert len(email.attachments) == (1 if attached else 0)
    else:
        with pytest.raises(EmailInputError, match="nesting limit"):
            parse_bytes(raw)


@pytest.mark.parametrize("attached", [False, True])
def test_excessive_mime_parts_are_rejected(attached):
    raw = (b"Content-Type: multipart/mixed; boundary=test\n\n"
           + b"--test\nContent-Type: text/plain\n\nhello\n" * MAX_MIME_PARTS
           + b"--test--\n")
    if attached:
        raw = b'Content-Disposition: attachment; filename="many.mime"\n' + raw
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
