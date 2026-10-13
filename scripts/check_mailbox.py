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

--detail adds diagnostics for flagged messages, still without message text:
the most common combinations of finding codes, which of PhishLens's own
built-in phrases matched (patterns show only as "(pattern N)", the Nth built-in pattern of that
signal), and the kind of link-text mismatch (whether the shown and the
real link domains belong to the sender, and whether DMARC passed).
"""

from __future__ import annotations

import argparse
import mailbox
import re
import sys
from collections import Counter
from pathlib import Path

from phishlens.analyzer import analyze
from phishlens.auth import parse_authentication_results
from phishlens.content import find_signals
from phishlens.domains import same_site
from phishlens.message import DEFAULT_MAX_BYTES, EmailInputError, ParsedEmail, parse_bytes
from phishlens.model import Model, ModelError, load_model
from phishlens.urls import extract_text_links, parse_html, strip_urls

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
            try:
                box = mailbox.mbox(path, create=False)
                keys = box.keys()
            except (OSError, mailbox.Error):
                yield None
                continue
            try:
                for key in keys:
                    raw = box.get_bytes(key)
                    yield raw if len(raw) <= DEFAULT_MAX_BYTES else None
            finally:
                box.close()


def _phrases(email: ParsedEmail) -> set[str]:
    """Built-in phrases that matched, as "code: phrase"; never message text."""
    visible = parse_html(email.html)[1] if email.html else ""
    name = email.sender.display_name if email.sender else ""
    text = strip_urls("\n".join((name, email.subject, email.text, visible)))
    found = set()
    for signal, matched in find_signals(text):
        lexicon = {p.lower() for p in signal.phrases}
        for m in matched:
            if m.lower() in lexicon:
                found.add(f"{signal.code}: {m}")
                continue
            # Name the built-in pattern that matched, never the matched text.
            number = next((n for n, pattern in enumerate(signal.patterns, 1) if re.fullmatch(pattern, m)), "?")
            found.add(f"{signal.code}: (pattern {number})")
    return found


def _link_kinds(email: ParsedEmail) -> set[str]:
    """How shown and real link domains relate to the sender, without naming them."""
    sender = email.sender.domain if email.sender else ""
    auth = parse_authentication_results(email.authentication_results)
    dmarc = "DMARC pass" if auth and auth.dmarc == "pass" else "no DMARC pass"
    links = (parse_html(email.html)[0] if email.html else []) + extract_text_links(email.text)
    kinds = set()
    for link in links:
        claimed = link.anchor_mismatch()
        if claimed and link.host:
            shown = "sender's site" if sender and same_site(claimed, sender) else "another site"
            real = "sender's site" if sender and same_site(link.host, sender) else "another site"
            kinds.add(f"text shows {shown}, link goes to {real}, {dmarc}")
    return kinds


def check(sources: list[Path], label: str, model: Model | None, detail: bool = False) -> str:
    verdicts: Counter[str] = Counter()
    codes_all: Counter[str] = Counter()
    codes_flagged: Counter[str] = Counter()
    scores: list[float] = []
    combos: Counter[str] = Counter()
    phrases: Counter[str] = Counter()
    link_kinds: Counter[str] = Counter()
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
            if detail:
                combos[" + ".join(sorted(rule_codes))] += 1
                phrases.update(_phrases(email))
                if "url.anchor_mismatch" in rule_codes:
                    link_kinds.update(_link_kinds(email))
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
    if detail:
        for title, counter, limit in (("Finding combinations on flagged messages", combos, 15),
                                      ("Built-in phrases matched on flagged messages", phrases, 40),
                                      ("Link-text mismatch kinds on flagged messages", link_kinds, 10)):
            lines += ["", f"{title} (messages)"]
            lines += [f"  {n:4}  {key}" for key, n in counter.most_common(limit)] or ["  none"]
    lines += ["", "No file names, subjects, addresses, links or message text are printed."]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("sources", nargs="+", type=Path, help=".eml files, directories or mbox files")
    parser.add_argument("--label", choices=("legitimate", "phishing"), required=True,
                        help="what these messages are known to be")
    parser.add_argument("--model", type=Path, help="also score with a model from scripts/train_model.py")
    parser.add_argument("--detail", action="store_true",
                        help="add code combinations, matched built-in phrases and link-mismatch kinds")
    args = parser.parse_args(argv)
    sources = [s.expanduser() for s in args.sources]
    missing = sum(not s.exists() for s in sources)
    if missing:
        print(f"check_mailbox: {missing} source path(s) do not exist", file=sys.stderr)
        return 1
    try:
        model = load_model(args.model.expanduser()) if args.model else None
    except (OSError, ModelError) as error:
        print(f"check_mailbox: cannot load model: {error}", file=sys.stderr)
        return 1
    print(check(sources, args.label, model, args.detail))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
