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


def test_untrusted_path_controls_are_escaped_in_errors(capsys):
    assert main(["analyze", "missing\x1b[2J\n.eml"]) == 1
    output = capsys.readouterr()
    assert "\x1b" not in output.err
    assert "missing\\x1b[2J\\x0a.eml" in output.err


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


def _fixture_dir(fixture_path):
    return fixture_path("clean_newsletter.eml").parent


def test_directory_gives_a_summary_sorted_by_score(fixture_path, capsys):
    assert main(["analyze", str(_fixture_dir(fixture_path))]) == 0
    out = capsys.readouterr().out
    assert "6 analysed, 0 not analysed" in out
    rows = [line for line in out.splitlines() if line.startswith("  HIGH RISK") or line.startswith("  LOW RISK")]
    assert rows[0].split()[2] == "100" and rows[-1].startswith("  LOW RISK")
    assert "high 5 · suspicious 0 · low 1 · not analysed 0" in out


def test_several_files_give_json_summary(fixture_path, capsys):
    paths = [str(fixture_path("clean_newsletter.eml")), str(fixture_path("dmarc_spoof.eml"))]
    assert main(["analyze", *paths, "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["summary"] == {"high": 1, "suspicious": 0, "low": 1, "analysed": 2, "not_analysed": 0}
    assert [r["level"] for r in data["reports"]] == ["low", "high"] and data["errors"] == []


def test_batch_fail_on_and_errors(fixture_path, tmp_path, capsys):
    clean = str(fixture_path("clean_newsletter.eml"))
    spoof = str(fixture_path("dmarc_spoof.eml"))
    assert main(["analyze", clean, spoof, "--fail-on", "high"]) == 2
    assert main(["analyze", clean, clean, "--fail-on", "high"]) == 0
    # A file that cannot be analysed makes the run incomplete, which takes precedence.
    assert main(["analyze", spoof, str(tmp_path / "missing.eml"), "--fail-on", "high"]) == 1
    captured = capsys.readouterr()
    assert "cannot read" in captured.err and "1 analysed, 1 not analysed" in captured.out


def test_directory_without_eml_files(tmp_path, capsys):
    (tmp_path / "notes.txt").write_text("not an email")
    assert main(["analyze", str(tmp_path)]) == 1
    assert "no .eml files" in capsys.readouterr().err


@pytest.mark.skipif(os.name == "nt", reason="Windows does not allow control characters in file names")
def test_batch_summary_escapes_untrusted_filenames(fixture_path, tmp_path, capsys):
    target = tmp_path / "evil\x1b[2J.eml"
    target.write_bytes(fixture_path("dmarc_spoof.eml").read_bytes())
    assert main(["analyze", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "\x1b" not in out and "evil\\x1b[2J.eml" in out
