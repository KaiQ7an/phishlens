"""Read the SPF, DKIM and DMARC verdicts the receiving mail server recorded.

PhishLens does not re-verify signatures or query DNS. It trusts the topmost
Authentication-Results header, which is the one added by the final receiving
server (your own mail provider). Headers further down can be forged by the
sender and are ignored.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_METHOD_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.IGNORECASE)


@dataclass(frozen=True)
class AuthVerdicts:
    spf: str | None
    dkim: str | None
    dmarc: str | None
    authserv_id: str | None

    def summary(self) -> str:
        parts = [f"{name.upper()} {value or 'missing'}" for name, value in
                 (("spf", self.spf), ("dkim", self.dkim), ("dmarc", self.dmarc))]
        return " · ".join(parts)


def parse_authentication_results(headers: list[str]) -> AuthVerdicts | None:
    if not headers:
        return None
    raw = " ".join(headers[0].split())
    authserv_id = raw.split(";", 1)[0].strip() or None
    found: dict[str, str] = {}
    for method, result in _METHOD_RE.findall(raw):
        found.setdefault(method.lower(), result.lower())
    return AuthVerdicts(found.get("spf"), found.get("dkim"), found.get("dmarc"), authserv_id)
