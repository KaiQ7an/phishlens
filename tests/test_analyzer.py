import pytest

from phishlens.analyzer import analyze, analyze_file
from phishlens.message import parse_bytes
from phishlens.scoring import Finding, risk_level, total_score


@pytest.mark.parametrize("name, level, required_codes", [
    ("dmarc_spoof.eml", "high", {"auth.dmarc_fail", "auth.spf_fail", "header.reply_to_mismatch",
                                 "url.brand_keyword", "content.credentials"}),
    ("lookalike_domain.eml", "high", {"header.from_lookalike", "header.display_name_brand", "url.lookalike"}),
    ("anchor_mismatch.eml", "high", {"url.anchor_mismatch", "url.ip_host", "url.form"}),
    ("suspicious_attachment.eml", "high", {"attachment.double_extension", "attachment.html", "content.payment"}),
    ("zh_fake_police.eml", "high", {"content.authority_non_gov", "content.secrecy", "content.payment"}),
])
def test_phishing_fixtures(fixture_path, name, level, required_codes):
    report = analyze_file(fixture_path(name))
    codes = {f.code for f in report.findings}
    assert required_codes <= codes, f"missing {required_codes - codes}"
    assert report.level == level


def test_clean_newsletter_is_low_risk(fixture_path):
    report = analyze_file(fixture_path("clean_newsletter.eml"))
    assert report.level == "low"
    assert report.score == 0
    assert report.findings == []


def test_passing_authentication_does_not_make_mail_safe(fixture_path):
    report = analyze_file(fixture_path("zh_fake_police.eml"))
    assert (report.auth.spf, report.auth.dkim, report.auth.dmarc) == ("pass", "pass", "pass")
    assert report.level == "high"


def test_keywords_inside_urls_do_not_count(fixture_path):
    report = analyze_file(fixture_path("zh_fake_police.eml"))
    authority = next(f for f in report.findings if f.code == "content.authority_non_gov")
    assert "'consulate'" not in authority.evidence


def test_every_finding_has_a_reason(fixture_path):
    for name in ("dmarc_spoof.eml", "anchor_mismatch.eml", "suspicious_attachment.eml"):
        for finding in analyze_file(fixture_path(name)).findings:
            assert finding.title and finding.severity in {"info", "low", "medium", "high"}


def test_government_sender_is_not_flagged_for_authority_language():
    raw = ("Authentication-Results: mx.receiver.example; spf=pass; dkim=pass; dmarc=pass\n"
           "From: Australian Taxation Office <notices@ato.gov.au>\nSubject: Notice\n\n"
           "This is not a police matter.\n").encode()
    codes = {f.code for f in analyze(parse_bytes(raw)).findings}
    assert "content.authority_non_gov" not in codes
    assert "content.authority" in codes


def test_score_is_capped_and_levelled():
    findings = [Finding("x", "high", "t")] * 5
    assert total_score(findings) == 100
    assert risk_level(0) == "low" and risk_level(20) == "suspicious" and risk_level(50) == "high"


def test_unknown_charset_does_not_hide_social_engineering():
    raw = (b"Authentication-Results: mx.receiver.example; spf=pass; dkim=pass; dmarc=pass\n"
           b"From: test@example.org\nContent-Type: text/plain; charset=unknown-charset\n\n"
           + "紧急：保证金需要转账".encode())
    report = analyze(parse_bytes(raw))
    assert report.email.parsing_warnings
    assert {f.code for f in report.findings} == {"content.urgency", "content.payment"}
    assert report.score == 20
