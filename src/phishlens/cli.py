"""Command-line entry point: `phishlens analyze mail.eml [--json]`."""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .analyzer import analyze_file
from .report import to_json, to_text

_LEVEL_RANK = {"low": 0, "suspicious": 1, "high": 2}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="phishlens", description="Explainable phishing email analysis.")
    parser.add_argument("--version", action="version", version=f"phishlens {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    analyze = commands.add_parser("analyze", help="analyse one .eml file")
    analyze.add_argument("path", help="path to an .eml file")
    analyze.add_argument("--json", action="store_true", help="print machine-readable JSON")
    analyze.add_argument("--fail-on", choices=("suspicious", "high"),
                         help="exit with status 2 when the verdict reaches this level")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        report = analyze_file(args.path)
    except OSError as error:
        print(f"phishlens: cannot read {args.path}: {error.strerror or error}", file=sys.stderr)
        return 1
    print(to_json(report) if args.json else to_text(report))
    if args.fail_on and _LEVEL_RANK[report.level] >= _LEVEL_RANK[args.fail_on]:
        return 2
    return 0
