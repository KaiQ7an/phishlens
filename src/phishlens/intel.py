"""Threat-intelligence lookups (planned for week 2).

Reputation services such as VirusTotal and URLhaus will plug in behind this
interface. Keys will be read from environment variables only
(PHISHLENS_VIRUSTOTAL_KEY, PHISHLENS_URLHAUS_KEY) and never stored in the repo.
Lookups will send only URLs and SHA-256 hashes, never message bodies.
Until then, analysis is fully offline.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class IntelVerdict:
    source: str
    malicious: bool
    detail: str = ""


class ThreatIntel(Protocol):
    def check_url(self, url: str) -> IntelVerdict | None: ...

    def check_sha256(self, sha256: str) -> IntelVerdict | None: ...


class OfflineIntel:
    """Default: no network access, no verdicts."""

    def check_url(self, url: str) -> IntelVerdict | None:
        return None

    def check_sha256(self, sha256: str) -> IntelVerdict | None:
        return None
