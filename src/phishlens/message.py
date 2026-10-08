"""Load an .eml file into a structured view of the parts PhishLens inspects.

Leaf attachments are decoded only so their size and SHA-256 can be recorded.
MIME container attachments use an explicitly labelled serialized representation.
Attachment contents are never written to disk, opened or executed.
"""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass, field
from email import policy
from email.errors import MessageError
from email.message import EmailMessage, Message
from email.parser import BytesParser
from pathlib import Path
from typing import BinaryIO

DEFAULT_MAX_BYTES = 25 * 1024 * 1024
MAX_MIME_PARTS = 1000
MAX_MIME_DEPTH = 30


class EmailInputError(ValueError):
    """The input cannot be analysed within the supported parsing limits."""


def _validate_limit(max_bytes: int) -> None:
    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes < 1:
        raise ValueError("max_bytes must be a positive integer")


def _check_size(size: int, max_bytes: int) -> None:
    if size > max_bytes:
        raise EmailInputError(f"email exceeds the {max_bytes:,}-byte size limit")


def _read_limited(stream: BinaryIO, max_bytes: int) -> bytes:
    chunks: list[bytes] = []
    remaining = max_bytes + 1
    while remaining:
        chunk = stream.read(min(remaining, 64 * 1024))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


@dataclass(frozen=True)
class Address:
    display_name: str
    address: str

    @property
    def domain(self) -> str:
        _, _, domain = self.address.rpartition("@")
        return domain.lower().rstrip(".")

    def __str__(self) -> str:
        return f"{self.display_name} <{self.address}>" if self.display_name else self.address


@dataclass(frozen=True)
class Attachment:
    filename: str
    content_type: str
    size: int
    sha256: str
    hash_basis: str = "decoded-payload"


@dataclass
class ParsedEmail:
    subject: str = ""
    date: str = ""
    sender: Address | None = None
    reply_to: list[Address] = field(default_factory=list)
    return_path: str = ""
    authentication_results: list[str] = field(default_factory=list)
    text: str = ""
    html: str = ""
    attachments: list[Attachment] = field(default_factory=list)
    parsing_warnings: list[str] = field(default_factory=list)


def _addresses(message: EmailMessage, name: str) -> list[Address]:
    header = message.get(name)
    if header is None:
        return []
    try:
        return [Address(a.display_name or "", a.addr_spec or "") for a in header.addresses]
    except AttributeError:  # malformed header: keep the raw value rather than drop it
        return [Address("", str(header).strip())]


def _decode_text(part: Message, warnings: list[str]) -> str:
    try:
        return part.get_content(errors="strict")
    except (LookupError, UnicodeDecodeError, KeyError):
        payload = part.get_payload(decode=True) or b""
        charset = part.get_content_charset() or "utf-8"
        try:
            text = payload.decode(charset, errors="replace")
        except LookupError:
            warnings.append(f"Unknown text charset '{charset}'; used UTF-8 with replacement characters.")
            return payload.decode("utf-8", errors="replace")
        warnings.append("Text could not be decoded normally; replacement characters may be present.")
        return text


def _is_attachment(part: Message) -> bool:
    return (part.get_content_disposition() == "attachment"
            or part.get_filename() is not None
            or part.get_content_type() in {"message/rfc822", "message/global"})


def _bounded_parts(message: Message) -> list[tuple[Message, bool]]:
    """Validate every part and mark descendants of attachments as out of scope.

    Attachment descendants still count toward the limits and defect warnings,
    but they must not contribute body text or attachments to the outer email.
    """
    parts: list[tuple[Message, bool]] = []
    pending = [(message, 0, False)]
    while pending:
        part, depth, inside_attachment = pending.pop()
        if depth > MAX_MIME_DEPTH:
            raise EmailInputError(f"email exceeds the MIME nesting limit of {MAX_MIME_DEPTH}")
        parts.append((part, inside_attachment))
        if len(parts) > MAX_MIME_PARTS:
            raise EmailInputError(f"email exceeds the MIME part limit of {MAX_MIME_PARTS}")
        if part.is_multipart():
            child_is_attached = inside_attachment or _is_attachment(part)
            pending.extend((child, depth + 1, child_is_attached)
                           for child in reversed(part.get_payload()))
    return parts


def _attachment_bytes(part: Message, warnings: list[str]) -> bytes:
    if part.is_multipart():
        # The parser represents these payloads as Message objects, so decoded
        # original bytes are unavailable. Serialize in memory, without reading
        # or extracting their contents as a separate email.
        warnings.append("MIME container attachment size and SHA-256 use a serialized "
                        "representation and may differ from the original attachment bytes.")
        try:
            return part.as_bytes(policy=policy.default)
        except UnicodeEncodeError:
            # Malformed multipart bodies may have become replacement text in
            # the stdlib parser; its byte generator cannot encode that text.
            warnings.append("Malformed MIME container attachment required text serialization; "
                            "replacement characters may be present.")
            return part.as_string(policy=policy.default).encode("utf-8", errors="surrogateescape")
    return part.get_payload(decode=True) or b""


_DEFECT_WARNINGS = {
    "NoBoundaryInMultipartDefect": "Multipart email has no boundary; some content may be missing.",
    "StartBoundaryNotFoundDefect": "Multipart start boundary was not found; some content may be missing.",
    "CloseBoundaryNotFoundDefect": "Multipart closing boundary was not found; the email may be truncated.",
    "MultipartInvariantViolationDefect": "Multipart content could not be separated into individual parts.",
    "MissingHeaderBodySeparatorDefect": "The separator between headers and body is missing.",
    "InvalidBase64PaddingDefect": "Base64 content has invalid padding; decoding may be incomplete.",
    "InvalidBase64CharactersDefect": "Base64 content contains invalid characters; decoding may be incomplete.",
    "InvalidBase64LengthDefect": "Base64 content has an invalid length; decoding may be incomplete.",
}


def parse_bytes(raw: bytes, *, max_bytes: int = DEFAULT_MAX_BYTES) -> ParsedEmail:
    _validate_limit(max_bytes)
    _check_size(len(raw), max_bytes)
    if not raw.strip():
        raise EmailInputError("email is empty")
    try:
        message = BytesParser(policy=policy.default).parsebytes(raw)
    except RecursionError as error:
        raise EmailInputError("email is too deeply nested to parse") from error
    except MessageError as error:
        raise EmailInputError(f"email could not be parsed: {error}") from error
    parts = _bounded_parts(message)
    senders = _addresses(message, "From")
    parsed = ParsedEmail(
        subject=str(message.get("Subject", "")),
        date=str(message.get("Date", "")),
        sender=senders[0] if senders else None,
        reply_to=_addresses(message, "Reply-To"),
        return_path=str(message.get("Return-Path", "")).strip().strip("<>"),
        authentication_results=[str(h) for h in message.get_all("Authentication-Results", [])],
    )

    text_parts: list[str] = []
    html_parts: list[str] = []
    for part, inside_attachment in parts:
        if inside_attachment:
            continue
        filename = part.get_filename()
        if _is_attachment(part):
            payload = _attachment_bytes(part, parsed.parsing_warnings)
            parsed.attachments.append(
                Attachment(
                    filename=filename or "(unnamed)",
                    content_type=part.get_content_type(),
                    size=len(payload),
                    sha256=hashlib.sha256(payload).hexdigest(),
                    hash_basis="serialized-mime" if part.is_multipart() else "decoded-payload",
                )
            )
        elif part.is_multipart():
            continue
        elif part.get_content_type() == "text/plain":
            text_parts.append(_decode_text(part, parsed.parsing_warnings))
        elif part.get_content_type() == "text/html":
            html_parts.append(_decode_text(part, parsed.parsing_warnings))

    # Decoding can add defects (notably invalid base64), so inspect them last.
    for part, _ in parts:
        for defect in part.defects:
            parsed.parsing_warnings.append(_DEFECT_WARNINGS.get(
                type(defect).__name__, "Malformed email content was detected; analysis may be incomplete."))
    parsed.parsing_warnings = list(dict.fromkeys(parsed.parsing_warnings))

    parsed.text = "\n".join(text_parts)
    parsed.html = "\n".join(html_parts)
    return parsed


def parse_file(path: str | Path, *, max_bytes: int = DEFAULT_MAX_BYTES) -> ParsedEmail:
    """Read a regular file, checking its size before a bounded read.

    Nonblocking open avoids waiting for a writer when the path is a FIFO.
    Checking the opened descriptor also covers paths that change during open.
    """
    _validate_limit(max_bytes)
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode):
            raise EmailInputError("input must be a regular email file")
        _check_size(metadata.st_size, max_bytes)
        raw = _read_limited(stream, max_bytes)
    return parse_bytes(raw, max_bytes=max_bytes)
