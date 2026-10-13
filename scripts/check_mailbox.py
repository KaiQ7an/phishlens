"""Measure PhishLens on your own mail without printing any of it.

Run this yourself on exported mail you know the answer for, such as a folder
of ordinary .eml files (--label legitimate) or messages you reported as
phishing (--label phishing). It prints only counts: verdicts, the false-alarm
or detection rate, how many messages each finding code fired on and, with
--model, the model's score spread. It never prints file names, subjects,
addresses, links or message text, and writes nothing.

    python -I scripts/check_mailbox.py ~/Downloads --label legitimate
    python -I scripts/check_mailbox.py ~/Mail/Inbox.mbox --label legitimate --model ~/Datasets/phishlens/model.json

Sources are .eml files, directories (searched for .eml files, recursively) and
mbox files. Share the output only if you are comfortable with these counts.
"""

from __future__ import annotations

import argparse
import mailbox
import sys
from collections import Counter
from pathlib import Path

from phishlens.analyzer import analyze
from phishlens.message import DEFAULT_MAX_BYTES, EmailInputError, parse_bytes
from phishlens.model import Model, load_model

MAX_FILES = 100_000


def raw_messages(sources: list[Path]):
    """Yield raw messages; count but never name the ones that cannot be read."""
    seen = 0
    for source in sources:
        if source.is_dir():
            paths = sorted(p for p in source.rglob("*") if p.suffix.lower() == ".eml" and p.is_file())
        else:
            paths = [source]
        for path in paths:
            seen += 1
            if seen > MAX_FILES:
                return
            if path.suffix.lower() == ".eml" or source.is_dir():
                try:
                    if path.stat().st_size <= DEFAULT_MAX_BYTES:
                        yield path.read_bytes()
                    else:
                        yield None
                except OSError:
                    yield None
                continue
            box = mailbox.mbox(path, create=False)
            try:
                for key in box.keys():
                    raw = box.get_bytes(key)
                    yield raw if len(raw) <= DEFAULT_MAX_BYTES else None
            finally:
                box.close()


def check(sources: list[Path], label: str, model: Model | None) -> str:
    verdicts: Counter[str] = Counter()
    codes_all: Counter[str] = Counter()
    codes_flagged: Counter[str] = Counter()
    scores: list[float] = []
    unreadable = 0
    for raw in raw_messages(sources):
        if raw is None:
            unreadable += 1
            continue
        try:
            email = parse_bytes(raw)
        except EmailInputError:
            unreadable += 1
            continue
        report = analyze(email, model=model)
        rule_codes = {f.code for f in report.findings if not f.code.startswith("model.")}
        verdicts[report.level] += 1
        codes_all.update(rule_codes)
        if report.level != "low":
            codes_flagged.update(rule_codes)
        if model is not None:
            scores.append(model.assess(email)[0])

    total = sum(verdicts.values())
    flagged = verdicts["suspicious"] + verdicts["high"]
    lines = [f"PhishLens mailbox check: {total} messages read as {label}, {unreadable} could not be read", ""]
    if not total:
        return "\n".join(lines + ["Nothing to report."])
    lines.append(f"Verdicts: low {verdicts['low']} · suspicious {verdicts['suspicious']} · high {verdicts['high']}")
    if label == "legitimate":
        lines.append(f"False alarms (suspicious or high): {flagged}/{total} ({flagged / total:.0%})")
    else:
        lines.append(f"Detected (suspicious or high): {flagged}/{total} ({flagged / total:.0%})")
    if model is not None:
        above = sum(score >= model.threshold for score in scores)
        ordered = sorted(scores)
        q = lambda f: ordered[min(len(ordered) - 1, int(f * len(ordered)))]  # noqa: E731
        lines.append(f"Model (threshold {model.threshold:.3f}): {above}/{len(scores)} above threshold; "
                     f"scores p10 {q(0.1):.2f} · median {q(0.5):.2f} · p90 {q(0.9):.2f}")
    for title, counter in (("Rule findings on flagged messages", codes_flagged),
                           ("Rule findings on all messages", codes_all)):
        lines += ["", f"{title} (code: messages)"]
        lines += [f"  {code}: {n}" for code, n in counter.most_common()] or ["  none"]
    lines += ["", "No file names, subjects, addresses, links or message text are printed."]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("sources", nargs="+", type=Path, help=".eml files, directories or mbox files")
    parser.add_argument("--label", choices=("legitimate", "phishing"), required=True,
                        help="what these messages are known to be")
    parser.add_argument("--model", type=Path, help="also score with a model from scripts/train_model.py")
    args = parser.parse_args(argv)
    model = load_model(args.model) if args.model else None
    print(check([s.expanduser() for s in args.sources], args.label, model))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
