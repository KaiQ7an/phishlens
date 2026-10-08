from dataclasses import replace
from html import escape

import pytest

from phishlens.analyzer import analyze
from phishlens.message import Address, Attachment, ParsedEmail, parse_bytes

_AUTH = "mx.receiver.example; spf=pass; dkim=pass; dmarc=pass"
_TRACKER = "https://campaign.rs6.net/tn.jsp?f=synthetic-token&c=sample&ch=sample"


def tracked_link(anchor="events.example.org", url=_TRACKER):
    return f'<a href="{escape(url, quote=True)}">{escape(anchor)}</a>'


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


def test_opaque_provider_tracking_route_retains_an_unverified_destination_warning():
    report = analyze(mailing_email(html=tracked_link()))
    warning = finding(report, "url.tracking_destination_unverified")
    assert warning.points == 5 and "final destination is unverified" in warning.title
    assert report.score == 10 and report.level == "low"
    assert not any(f.code == "url.anchor_mismatch" for f in report.findings)


@pytest.mark.parametrize("anchor", [
    "https://bad_domain.example.org", "https://-bad.example.org", "https://bad-.example.org",
    "https://events.example.org:invalid", "https://events.example.org:8443",
    "https://events.example.org:", "https://events.example.org:0443",
    "http://events.example.org:443", "https://events.example.org/%zz",
    "https://events.example.org/%6cogin", "https://events.example.org/?page=%256cogin",
    "https://events.example.org/\\login", "xn--caf-dma.example.org",
])
def test_malformed_encoded_or_nonstandard_visible_urls_keep_high_mismatch(anchor):
    report = analyze(mailing_email(html=tracked_link(anchor)))
    assert finding(report, "url.anchor_mismatch").points == 30
    assert not any(f.code == "url.tracking_destination_unverified" for f in report.findings)


@pytest.mark.parametrize("anchor", [
    "events.example.org", "events.example.org/news", "https://events.example.org/news",
    "https://events.example.org:443/news", "http://events.example.org:80/news",
])
def test_plain_visible_site_urls_can_receive_unverified_route_warning(anchor):
    report = analyze(mailing_email(html=tracked_link(anchor)))
    assert finding(report, "url.tracking_destination_unverified").points == 5


@pytest.mark.parametrize("anchor", ["monash.edu", "login.monash.edu", "micros0ft.com", "аbc.example", "events.example.org/login"])
@pytest.mark.parametrize("reverse", [False, True])
def test_later_serious_mismatch_to_same_tracker_host_is_not_hidden(anchor, reverse):
    links = [tracked_link(), tracked_link(anchor)]
    if reverse:
        links.reverse()
    report = analyze(mailing_email(html="".join(links)))
    assert finding(report, "header.reply_to_mismatch").points == 15
    assert finding(report, "url.anchor_mismatch").points == 30
    assert not any(f.code == "url.tracking_destination_unverified" for f in report.findings)


@pytest.mark.parametrize("url", [
    "https://rs6.net.evil.example/tn.jsp?f=sample",
    "https://evilrs6.net/tn.jsp?f=sample",
    "http://campaign.rs6.net/tn.jsp?f=sample",
    "https://user@campaign.rs6.net/tn.jsp?f=sample",
    "https://campaign.rs6.net:8443/tn.jsp?f=sample",
    "https://campaign.rs6.net:invalid/tn.jsp?f=sample",
    "https://campaign.rs6.net/other?f=sample",
    "https://campaign.rs6.net/tn.jsp?f=one&f=two",
    "https://campaign.rs6.net/tn.jsp?f=sample&url=https://evil.example",
    _TRACKER + "\n",
    " " + _TRACKER,
    _TRACKER.replace("campaign", "cam\tpaign"),
])
def test_nonmatching_or_malformed_route_keeps_high_mismatch(url):
    report = analyze(mailing_email(html=tracked_link(url=url)))
    assert finding(report, "url.anchor_mismatch").points == 30
    assert not any(f.code == "url.tracking_destination_unverified" for f in report.findings)


@pytest.mark.parametrize("headers", [
    [],
    ["mx.receiver.example; spf=pass; dkim=none; dmarc=pass"],
    ["mx.receiver.example; spf=fail; dkim=pass; dmarc=pass"],
    ["mx.receiver.example; spf=pass; dkim=fail; dmarc=pass"],
    ["mx.receiver.example; spf=pass; dkim=pass; dmarc=fail"],
    [_AUTH + "; dkim=fail"],
])
def test_unusable_or_failing_authentication_keeps_high_tracker_mismatch(headers):
    report = analyze(mailing_email(html=tracked_link(), authentication_results=headers))
    assert finding(report, "url.anchor_mismatch").points == 30
    assert not any(f.code == "url.tracking_destination_unverified" for f in report.findings)


def test_unknown_sender_keeps_high_tracker_mismatch():
    report = analyze(mailing_email(html=tracked_link(), sender=Address("Club", "news@ordinary.example")))
    assert finding(report, "url.anchor_mismatch").points == 30


def test_form_destination_does_not_gain_tracker_reduction():
    report = analyze(mailing_email(html=f'<form action="{escape(_TRACKER, quote=True)}"></form>'))
    assert finding(report, "url.form").points == 15
    assert finding(report, "header.reply_to_mismatch").points == 15
    assert not any(f.code == "url.tracking_destination_unverified" for f in report.findings)


@pytest.mark.parametrize("other_link", [
    '<form action="https://forms.example.org/submit"></form>',
    '<a href="https://203.0.113.9/news">News</a>',
    '<a href="https://micros0ft.com/news">News</a>',
    '<a href="https://user@updates.example.org/news">News</a>',
])
@pytest.mark.parametrize("reverse", [False, True])
def test_other_substantial_url_signals_disable_both_reductions(other_link, reverse):
    links = [tracked_link(), other_link]
    if reverse:
        links.reverse()
    report = analyze(mailing_email(html="".join(links)))
    assert finding(report, "header.reply_to_mismatch").points == 15
    assert finding(report, "url.anchor_mismatch").points == 30
    assert report.level == "high"
    assert not any(f.code == "url.tracking_destination_unverified" for f in report.findings)


def test_recorded_failure_points_remain_independent():
    report = analyze(mailing_email(html=tracked_link(), authentication_results=[
        "mx.receiver.example; spf=fail; dkim=fail; dmarc=fail"]))
    assert {"auth.spf_fail", "auth.dkim_fail", "auth.dmarc_fail", "url.anchor_mismatch"} <= {
        f.code for f in report.findings}
    assert report.level == "high"


@pytest.mark.parametrize("text", ["Please verify your account.", "Send a wire transfer.", "Keep this confidential."])
def test_substantial_content_signals_disable_both_routing_reductions(text):
    report = analyze(mailing_email(html=tracked_link(), text=text))
    assert finding(report, "header.reply_to_mismatch").points == 15
    assert finding(report, "url.anchor_mismatch").points == 30
    assert report.level == "high"


def test_risky_attachment_disables_routing_reductions():
    report = analyze(mailing_email(html=tracked_link(), attachments=[
        Attachment("invoice.pdf.exe", "application/octet-stream", 10, "a" * 64)]))
    assert finding(report, "header.reply_to_mismatch").points == 15
    assert finding(report, "url.anchor_mismatch").points == 30
    assert finding(report, "attachment.double_extension").points == 30
    assert report.level == "high"


@pytest.mark.parametrize("changes", [
    {"sender": Address("Microsoft Support", "news@shared1.ccsend.com")},
    {"reply_to": [Address("", "editor@club.example"), Address("", "help@micros0ft.com")]},
    {"reply_to": [Address("", "editor@club.example"), Address("", "broken")]},
])
def test_other_suspicious_headers_disable_routing_reductions(changes):
    report = analyze(mailing_email(html=tracked_link(), **changes))
    assert finding(report, "header.reply_to_mismatch").points == 15
    assert finding(report, "url.anchor_mismatch").points == 30
    assert report.level == "high"


def test_parsing_warning_keeps_normal_tracker_mismatch():
    report = analyze(mailing_email(html=tracked_link(), parsing_warnings=["Incomplete content."]))
    assert finding(report, "url.anchor_mismatch").points == 30


@pytest.mark.parametrize("identity", [
    "From: bad local@shared1.ccsend.com\nReply-To: editor@club.example",
    "From: news@shared1.ccsend.com\nReply-To: bad local@club.example",
    "From: news@shared1.ccsend.com\nFrom: other@shared1.ccsend.com\nReply-To: editor@club.example",
    "From: news@shared1.ccsend.com\nReply-To: editor@club.example\nReply-To: other@club.example",
])
def test_recovered_or_duplicate_identity_headers_disable_routing_reductions(identity):
    raw = (identity + "\nAuthentication-Results: " + _AUTH
           + "\nContent-Type: text/html; charset=utf-8\n\n" + tracked_link()).encode()
    email = parse_bytes(raw)
    report = analyze(email)
    assert email.parsing_warnings
    assert finding(report, "header.reply_to_mismatch").points == 15
    assert finding(report, "url.anchor_mismatch").points == 30
