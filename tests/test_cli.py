import json
import os
import subprocess
import sys

import pytest

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


def test_empty_file_returns_error_without_report(tmp_path, capsys):
    path = tmp_path / "empty.eml"
    path.write_bytes(b"")
    assert main(["analyze", str(path), "--json"]) == 1
    output = capsys.readouterr()
    assert output.out == ""
    assert "email is empty" in output.err


def test_cli_size_limit_can_be_overridden(tmp_path, capsys):
    path = tmp_path / "large.eml"
    path.write_bytes(b"From: test@example.org\n\n" + b"x" * (1024 * 1024))
    assert main(["analyze", str(path), "--max-size-mb", "1"]) == 1
    output = capsys.readouterr()
    assert output.out == "" and "size limit" in output.err
    assert main(["analyze", str(path), "--max-size-mb", "2", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["from"] == "test@example.org"


def test_large_limit_does_not_cause_large_allocation(fixture_path, capsys):
    assert main(["analyze", str(fixture_path("clean_newsletter.eml")),
                 "--max-size-mb", str(10 ** 30), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["score"] == 0


@pytest.mark.parametrize("value", ["0", "-1", "1.5", "invalid"])
def test_invalid_cli_size_limit(value, capsys):
    with pytest.raises(SystemExit) as error:
        main(["analyze", "unused.eml", f"--max-size-mb={value}"])
    assert error.value.code == 2
    assert "positive whole number" in capsys.readouterr().err


@pytest.mark.parametrize("json_output", [False, True])
def test_parsing_warnings_are_visible_in_reports(tmp_path, capsys, json_output):
    path = tmp_path / "bad-charset.eml"
    path.write_bytes(b"From: test@example.org\nContent-Type: text/plain; charset=unknown-charset\n\nhello")
    args = ["analyze", str(path)] + (["--json"] if json_output else [])
    assert main(args) == 0
    output = capsys.readouterr()
    assert output.err == ""
    if json_output:
        warnings = json.loads(output.out)["parsing_warnings"]
        assert any("unknown-charset" in warning for warning in warnings)
    else:
        assert "Parsing warnings (analysis may be incomplete)" in output.out
        assert "unknown-charset" in output.out


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs are unavailable on this platform")
def test_fifo_is_rejected_without_waiting_for_a_writer(tmp_path):
    path = tmp_path / "input.eml"
    os.mkfifo(path)
    result = subprocess.run([sys.executable, "-m", "phishlens", "analyze", str(path)],
                            capture_output=True, text=True, timeout=5)
    assert result.returncode == 1
    assert result.stdout == ""
    assert "regular email file" in result.stderr
    assert "Traceback" not in result.stderr
