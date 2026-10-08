"""Command-line entry point: `phishlens analyze mail.eml [--json]`."""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .analyzer import analyze_file
from .message import DEFAULT_MAX_BYTES, EmailInputError
from .report import to_json, to_text

_LEVEL_RANK = {"low": 0, "suspicious": 1, "high": 2}


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
    analyze = commands.add_parser("analyze", help="analyse one .eml file")
    analyze.add_argument("path", help="path to an .eml file")
    analyze.add_argument("--json", action="store_true", help="print machine-readable JSON")
    analyze.add_argument("--max-size-mb", type=_positive_int, default=DEFAULT_MAX_BYTES // (1024 * 1024),
                         help="maximum .eml size in MiB (default: %(default)s)")
    analyze.add_argument("--fail-on", choices=("suspicious", "high"),
                         help="exit with status 2 when the verdict reaches this level")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        report = analyze_file(args.path, max_bytes=args.max_size_mb * 1024 * 1024)
    except OSError as error:
        print(f"phishlens: cannot read {args.path}: {error.strerror or error}", file=sys.stderr)
        return 1
    except EmailInputError as error:
        print(f"phishlens: cannot analyse {args.path}: {error}", file=sys.stderr)
        return 1
    print(to_json(report) if args.json else to_text(report))
    if args.fail_on and _LEVEL_RANK[report.level] >= _LEVEL_RANK[args.fail_on]:
        return 2
    return 0
