from dataclasses import replace

import pytest

from phishlens.analyzer import analyze
from phishlens.message import Address, ParsedEmail

_AUTH = "mx.receiver.example; spf=pass; dkim=pass; dmarc=pass"


def mailing_email(**changes):
    return replace(ParsedEmail(subject="Example club newsletter",
                               sender=Address("Example Club", "news@shared1.ccsend.com"),
                               reply_to=[Address("Editor", "editor@club.example")],
                               authentication_results=[_AUTH], text="Our next club meeting is on Sunday."),
                   **changes)


def finding(report, code):
    return next(f for f in report.findings if f.code == code)


def test_provider_from_rewrite_retains_lower_weight_reply_warning():
    report = analyze(mailing_email())
    mismatch = finding(report, "header.reply_to_mismatch")
    assert mismatch.points == 5 and report.level == "low"
    assert "From rewriting" in mismatch.title and "club.example" in mismatch.evidence


def test_unknown_sender_keeps_normal_reply_warning():
    report = analyze(mailing_email(sender=Address("Example Club", "news@ordinary.example")))
    assert finding(report, "header.reply_to_mismatch").points == 15


@pytest.mark.parametrize("header", [
    "mx.receiver.example; spf=fail; dkim=pass; dmarc=pass",
    "mx.receiver.example; spf=pass; dkim=fail; dmarc=pass",
    "mx.receiver.example; spf=pass; dkim=pass; dmarc=fail",
    "mx.receiver.example; spf=pass; dmarc=pass",
    _AUTH + "; dkim=fail",
    _AUTH + "; spf=pass broken",
])
def test_auth_failure_missing_result_or_ambiguity_disables_reply_reduction(header):
    report = analyze(mailing_email(authentication_results=[header]))
    assert finding(report, "header.reply_to_mismatch").points == 15


def test_missing_authentication_disables_reply_reduction():
    report = analyze(mailing_email(authentication_results=[]))
    assert finding(report, "header.reply_to_mismatch").points == 15
    assert finding(report, "auth.missing").points == 5


def test_parsing_warning_disables_reply_reduction():
    report = analyze(mailing_email(parsing_warnings=["Content may be incomplete."]))
    assert finding(report, "header.reply_to_mismatch").points == 15


@pytest.mark.parametrize("domain", ["203.0.113.9", "bad_domain.example", "localhost", "аbc.example"])
def test_nonordinary_reply_domain_keeps_normal_warning(domain):
    report = analyze(mailing_email(reply_to=[Address("", "editor@" + domain)]))
    assert finding(report, "header.reply_to_mismatch").points == 15


@pytest.mark.parametrize("reverse", [False, True])
def test_later_reply_lookalike_cannot_be_hidden_by_an_ordinary_address(reverse):
    replies = [Address("", "editor@club.example"), Address("", "help@micros0ft.com")]
    if reverse:
        replies.reverse()
    report = analyze(mailing_email(reply_to=replies))
    assert finding(report, "header.reply_to_mismatch").points == 15
    assert finding(report, "header.reply_to_lookalike").points == 30


def test_malformed_reply_address_does_not_enable_route_reduction():
    report = analyze(mailing_email(reply_to=[Address("", "editor@club.example"), Address("", "broken")]))
    assert finding(report, "header.reply_to_mismatch").points == 15
    assert finding(report, "header.reply_to_malformed").points == 15


def test_provider_structure_does_not_suppress_social_engineering():
    report = analyze(mailing_email(text="紧急通知：警官要求保密并转账保证金到安全账户。"))
    codes = {f.code for f in report.findings}
    assert {"content.authority_non_gov", "content.secrecy", "content.payment", "content.urgency"} <= codes
    assert report.level == "high"
