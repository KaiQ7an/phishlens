"""Findings and the score built from them. Every point has a reason attached."""

from __future__ import annotations

from dataclasses import dataclass

SEVERITY_POINTS = {"info": 0, "low": 5, "medium": 15, "high": 30}
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


@dataclass(frozen=True)
class Finding:
    code: str
    severity: str
    title: str
    evidence: str = ""

    @property
    def points(self) -> int:
        return SEVERITY_POINTS[self.severity]


def total_score(findings: list[Finding]) -> int:
    return min(100, sum(f.points for f in findings))


def risk_level(score: int) -> str:
    if score >= 50:
        return "high"
    if score >= 20:
        return "suspicious"
    return "low"


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (SEVERITY_ORDER[f.severity], f.code))
