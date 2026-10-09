"""Command-line entry point: `phishlens analyze mail.eml [--json]`."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .analyzer import Report, analyze_file
from .display import json_display, terminal_text
from .message import DEFAULT_MAX_BYTES, EmailInputError
from .report import to_dict, to_json, to_text

_LEVEL_RANK = {"low": 0, "suspicious": 1, "high": 2}
_LEVEL_LABEL = {"high": "HIGH RISK", "suspicious": "SUSPICIOUS", "low": "LOW RISK"}


def _positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a positive whole number") from error
    if number < 1:
        raise argparse.ArgumentTypeError("must be a positive whole number")
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="phishlens", description="Explainable phishing email analysis.")
    parser.add_argument("--version", action="version", version=f"phishlens {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    analyze = commands.add_parser("analyze", help="analyse .eml files")
    analyze.add_argument("paths", nargs="+", metavar="path",
                         help="an .eml file, or a directory whose .eml files are analysed (not recursively); "
                              "several paths give a summary table")
    analyze.add_argument("--json", action="store_true", help="print machine-readable JSON")
    analyze.add_argument("--max-size-mb", type=_positive_int, default=DEFAULT_MAX_BYTES // (1024 * 1024),
                         help="maximum .eml size in MiB (default: %(default)s)")
    analyze.add_argument("--fail-on", choices=("suspicious", "high"),
                         help="exit with status 2 when a verdict reaches this level")
    return parser


def _expand(paths: list[str]) -> tuple[list[str], list[str], bool]:
    """Return (files, errors, batch). Directories contribute their .eml files."""
    files: list[str] = []
    errors: list[str] = []
    batch = len(paths) > 1
    for value in paths:
        path = Path(value)
        if not path.is_dir():
            files.append(value)
            continue
        batch = True
        found = sorted(str(child) for child in path.iterdir()
                       if child.suffix.lower() == ".eml" and child.is_file())
        if not found:
            errors.append(f"phishlens: no .eml files in {terminal_text(value)}")
        files.extend(found)
    return files, errors, batch


def _analyse(path: str, max_bytes: int) -> Report | str:
    try:
        return analyze_file(path, max_bytes=max_bytes)
    except OSError as error:
        return f"phishlens: cannot read {terminal_text(path)}: {terminal_text(str(error.strerror or error))}"
    except EmailInputError as error:
        return f"phishlens: cannot analyse {terminal_text(path)}: {terminal_text(str(error))}"


def _summary_text(reports: list[Report], error_count: int) -> str:
    rows = sorted(reports, key=lambda r: (-r.score, r.source))
    lines = [f"PhishLens summary: {len(reports)} analysed, {error_count} not analysed", "",
             f"  {'VERDICT':<11} {'SCORE':>5}  {'TOP FINDING':<52}  FILE"]
    for report in rows:
        top = terminal_text(report.findings[0].title) if report.findings else "-"
        if len(top) > 52:
            top = top[:51] + "…"
        lines.append(f"  {_LEVEL_LABEL[report.level]:<11} {report.score:>5}  {top:<52}  {terminal_text(report.source)}")
    counts = {level: sum(r.level == level for r in reports) for level in ("high", "suspicious", "low")}
    lines += ["", f"  high {counts['high']} · suspicious {counts['suspicious']} · low {counts['low']}"
                  f" · not analysed {error_count}",
              "  Run phishlens analyze on a single file to see its findings and evidence."]
    return "\n".join(lines)


def _summary_json(reports: list[Report], errors: list[str]) -> str:
    counts = {level: sum(r.level == level for r in reports) for level in ("high", "suspicious", "low")}
    data = {"summary": dict(counts, analysed=len(reports), not_analysed=len(errors)),
            "reports": [to_dict(report) for report in reports],
            "errors": errors}
    return json_display(json.dumps(data, ensure_ascii=False, indent=2))


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    max_bytes = args.max_size_mb * 1024 * 1024
    files, errors, batch = _expand(args.paths)
    reports: list[Report] = []
    for path in files:
        result = _analyse(path, max_bytes)
        if isinstance(result, str):
            errors.append(result)
        else:
            reports.append(result)
    for error in errors:
        print(error, file=sys.stderr)
    if not batch:
        if not reports:
            return 1
        print(to_json(reports[0]) if args.json else to_text(reports[0]))
    else:
        print(_summary_json(reports, errors) if args.json else _summary_text(reports, len(errors)))
    if errors:
        return 1
    if args.fail_on and any(_LEVEL_RANK[r.level] >= _LEVEL_RANK[args.fail_on] for r in reports):
        return 2
    return 0
