"""Escape untrusted controls while preserving readable Unicode report text."""

from __future__ import annotations

import json
import unicodedata


def _unsafe(character: str) -> bool:
    return unicodedata.category(character) in {"Cc", "Cf", "Cs", "Zl", "Zp"}


def terminal_text(value: str) -> str:
    """Prevent fields from moving the cursor, creating report lines, or hiding text."""
    pieces: list[str] = []
    for character in value:
        if not _unsafe(character):
            pieces.append(character)
        else:
            codepoint = ord(character)
            if codepoint <= 0xff:
                pieces.append(f"\\x{codepoint:02x}")
            elif codepoint <= 0xffff:
                pieces.append(f"\\u{codepoint:04x}")
            else:
                pieces.append(f"\\U{codepoint:08x}")
    return "".join(pieces)


def json_display(value: str) -> str:
    """Escape controls left literal by JSON encoding, preserving the parsed data.

    JSON already escapes control characters inside strings. Newlines here are
    generated indentation, so retain them. Use JSON escapes for other unsafe
    characters, including surrogate pairs for format controls outside the BMP.
    """
    return "".join(json.dumps(character, ensure_ascii=True)[1:-1]
                   if character != "\n" and _unsafe(character) else character
                   for character in value)
