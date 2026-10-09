"""Every labelled scenario must get the verdict its label calls for.

Expectations come from tests/scenarios.py and were written before the analyzer
was run. Known gaps are strict expected failures: when a change fixes one, this
test fails until its KNOWN_GAPS entry is removed.
"""

import pytest

from phishlens.analyzer import analyze
from phishlens.message import parse_bytes
from scenarios import KNOWN_GAPS, SCENARIOS, SPLITS


def _cases():
    for scenario in SCENARIOS:
        marks = ([pytest.mark.xfail(strict=True, reason=KNOWN_GAPS[scenario.id])]
                 if scenario.id in KNOWN_GAPS else [])
        yield pytest.param(scenario, id=scenario.id, marks=marks)


@pytest.mark.parametrize("scenario", list(_cases()))
def test_scenario_verdict(scenario):
    report = analyze(parse_bytes(scenario.raw), source=scenario.id)
    found = ", ".join(f.code for f in report.findings) or "no findings"
    if scenario.label == "phishing":
        assert report.level != "low", f"missed phishing ({report.score}): {found}"
    else:
        assert report.level == "low", f"false alarm, {report.level} ({report.score}): {found}"


def test_scenario_metadata_is_consistent():
    ids = [s.id for s in SCENARIOS]
    assert len(ids) == len(set(ids))
    assert set(KNOWN_GAPS) <= set(ids)
    for scenario in SCENARIOS:
        assert scenario.split in SPLITS and scenario.id.startswith(scenario.split + "/")
        assert scenario.label in {"legitimate", "phishing"}


def test_both_splits_contain_both_labels():
    for split in SPLITS:
        labels = {s.label for s in SCENARIOS if s.split == split}
        assert labels == {"legitimate", "phishing"}
