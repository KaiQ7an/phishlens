"""Load an .eml file into a structured view of the parts PhishLens inspects.

Attachments are decoded only so their size and SHA-256 can be recorded; their
contents are never written to disk, opened or executed.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from email import policy
from email.message import EmailMessage, Message
from email.parser import BytesParser
from pathlib import Path


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


def _addresses(message: EmailMessage, name: str) -> list[Address]:
    header = message.get(name)
    if header is None:
        return []
    try:
        return [Address(a.display_name or "", a.addr_spec or "") for a in header.addresses]
    except AttributeError:  # malformed header: keep the raw value rather than drop it
        return [Address("", str(header).strip())]


def _decode_text(part: Message) -> str:
    try:
        return part.get_content()
    except (LookupError, UnicodeDecodeError, KeyError):
        payload = part.get_payload(decode=True) or b""
        return payload.decode(part.get_content_charset() or "utf-8", errors="replace")


def parse_bytes(raw: bytes) -> ParsedEmail:
    message = BytesParser(policy=policy.default).parsebytes(raw)
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
    for part in message.walk():
        if part.is_multipart():
            continue
        disposition = part.get_content_disposition()
        filename = part.get_filename()
        if disposition == "attachment" or (filename and disposition != "inline"):
            payload = part.get_payload(decode=True) or b""
            parsed.attachments.append(
                Attachment(
                    filename=filename or "(unnamed)",
                    content_type=part.get_content_type(),
                    size=len(payload),
                    sha256=hashlib.sha256(payload).hexdigest(),
                )
            )
        elif part.get_content_type() == "text/plain":
            text_parts.append(_decode_text(part))
        elif part.get_content_type() == "text/html":
            html_parts.append(_decode_text(part))

    parsed.text = "\n".join(text_parts)
    parsed.html = "\n".join(html_parts)
    return parsed


def parse_file(path: str | Path) -> ParsedEmail:
    return parse_bytes(Path(path).read_bytes())
