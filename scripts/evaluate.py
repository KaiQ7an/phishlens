"""Measure PhishLens on the labelled synthetic scenarios in tests/scenarios.py.

A phishing scenario is a true positive when the verdict is suspicious or high;
a legitimate scenario is a true negative only when the verdict is low. Results
are reported separately for the dev split (which may guide rule changes) and
each holdout split (which must not), so tuning cannot hide in the totals.

These are small synthetic sets written for regression checking. The numbers
describe behaviour on these scenarios, not accuracy on real email.

    python scripts/evaluate.py            # readable summary
    python scripts/evaluate.py --markdown # table for documentation
    python scripts/evaluate.py --json     # machine-readable results
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))

from phishlens.analyzer import analyze  # noqa: E402
from phishlens.message import parse_bytes  # noqa: E402
from scenarios import SCENARIOS, SPLITS, Scenario  # noqa: E402


@dataclass(frozen=True)
class Outcome:
    scenario: Scenario
    level: str
    score: int
    codes: tuple[str, ...]

    @property
    def flagged(self) -> bool:
        return self.level != "low"

    @property
    def correct(self) -> bool:
        return self.flagged == (self.scenario.label == "phishing")


def run() -> list[Outcome]:
    outcomes = []
    for scenario in SCENARIOS:
        report = analyze(parse_bytes(scenario.raw), source=scenario.id)
        outcomes.append(Outcome(scenario, report.level, report.score,
                                tuple(f.code for f in report.findings)))
    return outcomes


def metrics(outcomes: list[Outcome]) -> dict:
    tp = sum(o.flagged and o.scenario.label == "phishing" for o in outcomes)
    fn = sum(not o.flagged and o.scenario.label == "phishing" for o in outcomes)
    fp = sum(o.flagged and o.scenario.label == "legitimate" for o in outcomes)
    tn = sum(not o.flagged and o.scenario.label == "legitimate" for o in outcomes)
    return {
        "scenarios": len(outcomes), "true_positive": tp, "false_negative": fn,
        "false_positive": fp, "true_negative": tn,
        "precision": round(tp / (tp + fp), 3) if tp + fp else None,
        "recall": round(tp / (tp + fn), 3) if tp + fn else None,
        "accuracy": round((tp + tn) / len(outcomes), 3) if outcomes else None,
    }


def by_split(outcomes: list[Outcome]) -> dict[str, dict]:
    splits = {name: [o for o in outcomes if o.scenario.split == name] for name in SPLITS}
    splits["all"] = outcomes
    return {name: metrics(items) for name, items in splits.items()}


def _pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.0%}"


def to_text(outcomes: list[Outcome]) -> str:
    lines = ["PhishLens evaluation on labelled synthetic scenarios", ""]
    lines.append(f"{'split':<9} {'n':>3} {'TP':>3} {'FN':>3} {'FP':>3} {'TN':>3} {'precision':>10} {'recall':>7} {'accuracy':>9}")
    for name, m in by_split(outcomes).items():
        lines.append(f"{name:<9} {m['scenarios']:>3} {m['true_positive']:>3} {m['false_negative']:>3} "
                     f"{m['false_positive']:>3} {m['true_negative']:>3} {_pct(m['precision']):>10} "
                     f"{_pct(m['recall']):>7} {_pct(m['accuracy']):>9}")
    wrong = [o for o in outcomes if not o.correct]
    lines += ["", f"Misclassified ({len(wrong)})"]
    for o in wrong:
        kind = "missed phishing" if o.scenario.label == "phishing" else "false alarm"
        lines.append(f"  {o.scenario.id:<42} {kind:<16} {o.level:<10} {o.score:>3}  {', '.join(o.codes) or '-'}")
    return "\n".join(lines)


def to_markdown(outcomes: list[Outcome]) -> str:
    rows = ["| Split | Scenarios | Detected phishing | Missed phishing | False alarms | Precision | Recall |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: |"]
    for name, m in by_split(outcomes).items():
        rows.append(f"| {name} | {m['scenarios']} | {m['true_positive']} | {m['false_negative']} | "
                    f"{m['false_positive']} | {_pct(m['precision'])} | {_pct(m['recall'])} |")
    return "\n".join(rows)


def to_json(outcomes: list[Outcome]) -> str:
    return json.dumps({
        "metrics": by_split(outcomes),
        "scenarios": [{"id": o.scenario.id, "split": o.scenario.split, "label": o.scenario.label,
                       "level": o.level, "score": o.score, "correct": o.correct, "findings": list(o.codes)}
                      for o in outcomes],
    }, ensure_ascii=False, indent=2)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--markdown", action="store_true", help="print a Markdown metrics table")
    group.add_argument("--json", action="store_true", help="print machine-readable results")
    args = parser.parse_args(argv)
    outcomes = run()
    print(to_markdown(outcomes) if args.markdown else to_json(outcomes) if args.json else to_text(outcomes))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
