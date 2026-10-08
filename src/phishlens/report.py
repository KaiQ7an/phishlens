"""Render a report as readable text or JSON."""

from __future__ import annotations

import json
from dataclasses import asdict

from .analyzer import Report

_LEVEL_LABEL = {"high": "HIGH RISK", "suspicious": "SUSPICIOUS", "low": "LOW RISK"}


def to_dict(report: Report) -> dict:
    email = report.email
    return {
        "source": report.source,
        "subject": email.subject,
        "from": str(email.sender) if email.sender else None,
        "date": email.date,
        "authentication": asdict(report.auth) if report.auth else None,
        "score": report.score,
        "level": report.level,
        "findings": [dict(asdict(f), points=f.points) for f in report.findings],
        "links": [{"url": l.url, "host": l.host, "anchor_text": l.anchor_text, "source": l.source}
                  for l in report.links],
        "attachments": [asdict(a) for a in report.attachments],
    }


def to_json(report: Report) -> str:
    return json.dumps(to_dict(report), ensure_ascii=False, indent=2)


def to_text(report: Report) -> str:
    email = report.email
    lines = [
        f"PhishLens report: {report.source}" if report.source else "PhishLens report",
        f"  Subject : {email.subject}",
        f"  From    : {email.sender if email.sender else '(missing)'}",
        f"  Auth    : {report.auth.summary() + (f'  (by {report.auth.authserv_id})' if report.auth.authserv_id else '') if report.auth else 'not recorded'}",
        "",
        f"  Verdict : {_LEVEL_LABEL[report.level]}  (score {report.score}/100)",
        "",
    ]
    if report.findings:
        lines.append("Findings")
        for f in report.findings:
            lines.append(f"  [{f.severity.upper():<6} +{f.points:>2}] {f.title}")
            if f.evidence:
                lines.append(f"               evidence: {f.evidence}")
    else:
        lines.append("Findings\n  none")
    lines.append("")
    lines.append(f"Links ({len(report.links)})")
    for link in report.links:
        text = f'  "{link.anchor_text}"' if link.anchor_text else ""
        lines.append(f"  - {link.display_host() or '(no host)'}  <- {link.url}{text}")
    lines.append("")
    lines.append(f"Attachments ({len(report.attachments)})")
    for a in report.attachments:
        lines.append(f"  - {a.filename}  {a.content_type}, {a.size} bytes, sha256 {a.sha256[:16]}…")
    return "\n".join(lines)
