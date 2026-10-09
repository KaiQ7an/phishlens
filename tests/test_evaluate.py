import importlib.util
import sys
from pathlib import Path

_PATH = Path(__file__).resolve().parents[1] / "scripts" / "evaluate.py"
_spec = importlib.util.spec_from_file_location("evaluate", _PATH)
evaluate = importlib.util.module_from_spec(_spec)
sys.modules["evaluate"] = evaluate  # dataclasses look up their defining module
_spec.loader.exec_module(evaluate)


def test_every_split_and_kind_is_reported_consistently():
    outcomes = evaluate.run()
    metrics = evaluate.by_split(outcomes)
    assert metrics["all"]["scenarios"] == len(outcomes)
    assert sum(metrics[name]["scenarios"] for name in evaluate.SPLITS) == len(outcomes)
    for name, counts in evaluate.by_kind(outcomes).items():
        split, kind = name.split("/")
        assert split in evaluate.SPLITS and kind in {"variant", "new"}
        assert 0 <= counts["detected"] <= counts["phishing"]
