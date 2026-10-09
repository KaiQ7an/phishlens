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


def _email(display_name, domain, body):
    raw = (f"Authentication-Results: mx.receiver.example; spf=pass; dkim=pass; dmarc=pass\n"
           f"From: {display_name} <notice@{domain}>\nSubject: Notice\n\n{body}\n").encode()
    return parse_bytes(raw)


def test_authority_claimed_only_in_display_name_is_flagged():
    codes = {f.code for f in analyze(_email("=?utf-8?b?5YWs5a6J5bGA?=", "cn-police-notice.example",
                                            "Please read this notice.")).findings}
    assert "content.authority_non_gov" in codes  # display name decodes to 公安局


def test_display_name_authority_from_government_domain_is_not_escalated():
    codes = {f.code for f in analyze(_email("Victoria Police", "police.vic.gov.au", "Community forum on Thursday.")).findings}
    assert "content.authority_non_gov" not in codes


def test_telling_the_reader_not_to_call_the_police_is_secrecy():
    for body in ("不要报警，按我们说的做。", "Don't call the police or anyone else."):
        codes = {f.code for f in analyze(_email("Helper", "mail-host.example", body)).findings}
        assert "content.secrecy" in codes


def test_bank_detail_changes_and_parcel_fees_are_payment_requests():
    for body in ("Please update our bank details before the next invoice.",
                 "A redelivery fee of $2.95 is required.", "请支付清关费后放行包裹。"):
        codes = {f.code for f in analyze(_email("Notice", "mail-host.example", body)).findings}
        assert "content.payment" in codes, body


def test_money_before_any_meeting_is_a_remote_deal():
    for body in ("I am currently overseas so I will mail you the keys.", "我人在国外，无法看房，先付押金。"):
        codes = {f.code for f in analyze(_email("Landlord", "mail-host.example", body)).findings}
        assert "content.remote_deal" in codes, body


def test_qr_code_requests_are_flagged():
    for body in ("Scan the QR code to continue.", "请扫描二维码完成认证。"):
        codes = {f.code for f in analyze(_email("IT", "mail-host.example", body)).findings}
        assert "content.qr_code" in codes, body


def test_microsoft_product_names_stand_for_the_microsoft_brand():
    codes = {f.code for f in analyze(_email("Jordan via SharePoint", "files-share.example", "Shared a file.")).findings}
    assert "header.display_name_brand" in codes
    codes = {f.code for f in analyze(_email("Jordan via SharePoint", "sharepointonline.com", "Shared a file.")).findings}
    assert "header.display_name_brand" not in codes


def test_product_names_in_domains_are_brand_keywords():
    from phishlens.domains import find_lookalike
    assert find_lookalike("onedrive-files.example").imitates == "microsoft.com"
    assert find_lookalike("australiapost-tracking.example").imitates == "auspost.com.au"
    assert find_lookalike("my-sharepoint.example").technique == "brand-keyword"


def test_tax_office_claims_from_non_government_domains_are_escalated():
    report = analyze(_email("Australian Taxation Office", "refund-centre.example", "You are owed a refund."))
    assert "content.authority_non_gov" in {f.code for f in report.findings}
    report = analyze(_email("Australian Taxation Office", "ato.gov.au", "Your return has been processed."))
    assert "content.authority_non_gov" not in {f.code for f in report.findings}


def test_guaranteed_returns_are_investment_lures():
    for body in ("Guaranteed returns of 30% per month.", "导师带单，稳赚不赔。"):
        codes = {f.code for f in analyze(_email("Mentor", "mail-host.example", body)).findings}
        assert "content.investment" in codes, body
    codes = {f.code for f in analyze(_email("Broker", "mail-host.example",
                                            "Your statement shows portfolio returns for September.")).findings}
    assert "content.investment" not in codes


def test_meta_brands_are_protected():
    from phishlens.domains import find_lookalike
    assert find_lookalike("instagram-verify-team.example").imitates == "instagram.com"
    assert find_lookalike("meta-analysis.example") is None
    codes = {f.code for f in analyze(_email("Meta Support", "page-review.example", "Hello.")).findings}
    assert "header.display_name_brand" in codes
    codes = {f.code for f in analyze(_email("Meta", "facebookmail.com", "Hello.")).findings}
    assert "header.display_name_brand" not in codes


def test_account_takedown_threats_are_flagged():
    for body in ("Your page will be disabled unless you submit an appeal.", "您的账号将被封禁。"):
        codes = {f.code for f in analyze(_email("Support", "mail-host.example", body)).findings}
        assert "content.account_threat" in codes, body


@pytest.mark.parametrize("code, body", [
    ("content.job_offer", "Work from home, no experience needed."),
    ("content.job_offer", "在家兼职，日结佣金。"),
    ("content.new_contact", "I lost my phone so this is my new number."),
    ("content.new_contact", "我手机坏了，换号了。"),
    ("content.favour", "Are you free? I need a quick favour."),
    ("content.favour", "帮个忙，我在开会。"),
    ("content.payment", "Can you transfer $500 tonight?"),
    ("content.payment", "需要先垫付本金。"),
])
def test_round_three_signals(code, body):
    assert code in {f.code for f in analyze(_email("Sender", "mail-host.example", body)).findings}


def test_relative_asking_for_money_from_new_contact_is_suspicious():
    report = analyze(_email("Jack", "mail-host.example",
                            "Hi Mum, I lost my phone. Can you transfer $1,800 to my flatmate?"))
    assert report.level != "low"
    report = analyze(_email("Jack", "mail-host.example", "Hi Mum, I lost my phone but the number is the same."))
    assert report.level == "low"


def test_docusign_is_protected():
    codes = {f.code for f in analyze(_email("DocuSign", "esign-notify.example", "Please sign.")).findings}
    assert "header.display_name_brand" in codes
    codes = {f.code for f in analyze(_email("Agent via DocuSign", "docusign.net", "Please sign.")).findings}
    assert "header.display_name_brand" not in codes
