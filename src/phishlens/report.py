"""Render a report as readable text or JSON."""

from __future__ import annotations

import json
from dataclasses import asdict

from .analyzer import Report
from .display import json_display, terminal_text

_LEVEL_LABEL = {"high": "HIGH RISK", "suspicious": "SUSPICIOUS", "low": "LOW RISK"}


def to_dict(report: Report) -> dict:
    email = report.email
    return {
        "source": report.source,
        "subject": email.subject,
        "from": str(email.sender) if email.sender else None,
        "date": email.date,
        "authentication": dict(asdict(report.auth), verified=False) if report.auth else None,
        "parsing_warnings": email.parsing_warnings,
        "score": report.score,
        "level": report.level,
        "findings": [dict(asdict(f), points=f.points) for f in report.findings],
        "links": [{"url": l.url, "host": l.host, "anchor_text": l.anchor_text, "source": l.source}
                  for l in report.links],
        "attachments": [asdict(a) for a in report.attachments],
    }


def to_json(report: Report) -> str:
    return json_display(json.dumps(to_dict(report), ensure_ascii=False, indent=2))


def to_text(report: Report) -> str:
    email = report.email
    auth = "not recorded"
    if report.auth:
        auth = terminal_text(report.auth.summary())
        if report.auth.authserv_id:
            auth += f"  (by {terminal_text(report.auth.authserv_id)})"
        auth += "  (recorded, unverified)"
    lines = [
        f"PhishLens report: {terminal_text(report.source)}" if report.source else "PhishLens report",
        f"  Subject : {terminal_text(email.subject)}",
        f"  From    : {terminal_text(str(email.sender)) if email.sender else '(missing)'}",
        f"  Auth    : {auth}",
        "",
        f"  Verdict : {_LEVEL_LABEL[report.level]}  (score {report.score}/100)",
        "",
    ]
    if email.parsing_warnings:
        lines.append("Parsing warnings (analysis may be incomplete)")
        lines.extend(f"  - {terminal_text(warning)}" for warning in email.parsing_warnings)
        lines.append("")
    if report.auth and report.auth.warnings:
        lines.append("Authentication warnings")
        lines.extend(f"  - {terminal_text(warning)}" for warning in report.auth.warnings)
        lines.append("")
    if report.findings:
        lines.append("Findings")
        for f in report.findings:
            lines.append(f"  [{f.severity.upper():<6} +{f.points:>2}] {terminal_text(f.title)}")
            if f.evidence:
                lines.append(f"               evidence: {terminal_text(f.evidence)}")
    else:
        lines.append("Findings\n  none")
    lines.append("")
    lines.append(f"Links ({len(report.links)})")
    for link in report.links:
        text = f'  "{terminal_text(link.anchor_text)}"' if link.anchor_text else ""
        lines.append(f"  - {terminal_text(link.display_host()) or '(no host)'}  <- {terminal_text(link.url)}{text}")
    lines.append("")
    lines.append(f"Attachments ({len(report.attachments)})")
    for a in report.attachments:
        lines.append(f"  - {terminal_text(a.filename)}  {terminal_text(a.content_type)}, {a.size} bytes, sha256 {a.sha256[:16]}…")
        if a.hash_basis != "decoded-payload":
            lines.append(f"    hash basis: {terminal_text(a.hash_basis)} (may differ from original attachment bytes)")
    return "\n".join(lines)
