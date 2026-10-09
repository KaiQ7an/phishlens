import json

import pytest

from phishlens.analyzer import analyze
from phishlens.cli import main
from phishlens.domains import find_lookalike, load_brand_file, protected_domains
from phishlens.message import parse_bytes


def _email(display_name, domain, body="Please review your account."):
    raw = (f"Authentication-Results: mx.receiver.example; spf=pass; dkim=pass; dmarc=pass\n"
           f"From: {display_name} <notice@{domain}>\nSubject: Notice\n\n{body}\n").encode()
    return parse_bytes(raw)


def _write(tmp_path, value):
    path = tmp_path / "brands.json"
    path.write_text(json.dumps(value) if not isinstance(value, str) else value, encoding="utf-8")
    return path


def test_custom_brands_apply_only_inside_one_analysis():
    brands = {"acmebank": ("acmebank.com.au",)}
    email = _email("AcmeBank Security", "acmebank-alerts.example")
    codes = {f.code for f in analyze(email, brands=brands).findings}
    assert {"header.display_name_brand", "header.from_lookalike"} <= codes
    # Nothing leaks into the next analysis or into module-level lookups.
    assert "header.display_name_brand" not in {f.code for f in analyze(email).findings}
    assert find_lookalike("acmebank-alerts.example") is None
    assert "acmebank.com.au" not in protected_domains()


def test_custom_brand_domains_are_trusted_senders():
    brands = {"acmebank": ("acmebank.com.au",)}
    codes = {f.code for f in analyze(_email("AcmeBank", "acmebank.com.au"), brands=brands).findings}
    assert "header.display_name_brand" not in codes


def test_custom_domains_extend_builtin_brands():
    brands = {"monash": ("monashcollege.edu.au",)}
    codes = {f.code for f in analyze(_email("Monash College", "monashcollege.edu.au"), brands=brands).findings}
    assert "header.display_name_brand" not in codes


def test_brand_file_is_normalised(tmp_path):
    path = _write(tmp_path, {"  Acme   Bank ": ["ACME.com.au", "acme.com.au", "acmebank.com."]})
    assert load_brand_file(path) == {"acme bank": ("acme.com.au", "acmebank.com")}


@pytest.mark.parametrize("value, reason", [
    ("[]", "expected an object"),
    ("{not json", "not valid UTF-8 JSON"),
    ({"ab": ["ab.com"]}, "3-40 letters"),
    ({"acme": "acme.com"}, "list of 1-20"),
    ({"acme": []}, "list of 1-20"),
    ({"acme": ["https://acme.com"]}, "registrable domain"),
    ({"acme": ["mail.acme.com"]}, "registrable domain"),
    ({"acme": ["192.0.2.1"]}, "registrable domain"),
])
def test_invalid_brand_files_are_rejected(tmp_path, value, reason):
    with pytest.raises(ValueError, match=reason):
        load_brand_file(_write(tmp_path, value))


def test_oversized_brand_file_is_rejected(tmp_path):
    path = tmp_path / "brands.json"
    path.write_bytes(b" " * (64 * 1024 + 1))
    with pytest.raises(ValueError, match="larger than"):
        load_brand_file(path)


def test_cli_uses_brand_file(tmp_path, capsys):
    eml = tmp_path / "acme.eml"
    eml.write_bytes(b"From: AcmeBank Security <notice@acmebank-alerts.example>\nSubject: Notice\n\nHello.\n")
    brands = _write(tmp_path, {"acmebank": ["acmebank.com.au"]})
    assert main(["analyze", str(eml), "--json"]) == 0
    codes = {f["code"] for f in json.loads(capsys.readouterr().out)["findings"]}
    assert "header.display_name_brand" not in codes
    assert main(["analyze", str(eml), "--json", "--brands", str(brands)]) == 0
    codes = {f["code"] for f in json.loads(capsys.readouterr().out)["findings"]}
    assert "header.display_name_brand" in codes


def test_cli_reports_bad_brand_files(fixture_path, tmp_path, capsys):
    clean = str(fixture_path("clean_newsletter.eml"))
    assert main(["analyze", clean, "--brands", str(tmp_path / "missing.json")]) == 1
    assert "cannot read brands file" in capsys.readouterr().err
    bad = _write(tmp_path, {"acme": ["not a domain"]})
    assert main(["analyze", clean, "--brands", str(bad)]) == 1
    assert "invalid brands file" in capsys.readouterr().err
