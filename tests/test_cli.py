import json

from phishlens.cli import main


def test_text_report(fixture_path, capsys):
    assert main(["analyze", str(fixture_path("dmarc_spoof.eml"))]) == 0
    out = capsys.readouterr().out
    assert "HIGH RISK" in out and "DMARC failed" in out


def test_json_report(fixture_path, capsys):
    assert main(["analyze", str(fixture_path("clean_newsletter.eml")), "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["level"] == "low" and data["score"] == 0
    assert data["links"][0]["host"] == "www.example.org"


def test_fail_on_sets_exit_code(fixture_path):
    assert main(["analyze", str(fixture_path("anchor_mismatch.eml")), "--fail-on", "suspicious"]) == 2
    assert main(["analyze", str(fixture_path("clean_newsletter.eml")), "--fail-on", "suspicious"]) == 0


def test_missing_file(capsys):
    assert main(["analyze", "does-not-exist.eml"]) == 1
    assert "cannot read" in capsys.readouterr().err
