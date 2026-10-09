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


def test_police_mentioned_in_passing_is_not_an_impersonation():
    body = "If you see suspicious behaviour, contact Victoria Police on 000."
    codes = {f.code for f in analyze(_email("Campus Security", "uni.example.edu", body)).findings}
    assert "content.authority_non_gov" not in codes and "content.authority" in codes
    codes = {f.code for f in analyze(_email("Campus Security", "uni.example.edu",
                                            "Police: pay the fine by bank transfer today.")).findings}
    assert "content.authority_non_gov" in codes


def test_wallet_recovery_phrase_requests_are_high_risk():
    report = analyze(_email("Wallet", "mail-host.example", "Confirm your seed phrase to keep access."))
    assert ("content.wallet_secret", "high") in {(f.code, f.severity) for f in report.findings}


def test_gift_card_codes_are_high_risk_but_receipts_are_not():
    codes = {f.code for f in analyze(_email("Appeal", "mail-host.example",
                                            "Buy gift cards and reply with the card numbers.")).findings}
    assert "content.gift_card_codes" in codes
    codes = {f.code for f in analyze(_email("Store", "mail-host.example",
                                            "Gift card $50. The gift card code was sent to the recipient.")).findings}
    assert "content.gift_card_codes" not in codes


@pytest.mark.parametrize("body, flagged", [
    ("$289.99 has been charged. To cancel, call 1-800-555-0199.", True),
    ("会员将自动续费899元，如需取消请致电 400-800-1234。", True),
    ("If you didn't make this transaction, call us on 13 22 21.", False),  # short service number
    ("Your renewal is due 2026-11-01. Call us with questions.", False),    # a date is not a number to call
    ("Call 1-800-555-0199 to book a table.", False),                       # no charge to dispute
])
def test_callback_numbers(body, flagged):
    codes = {f.code for f in analyze(_email("Billing", "mail-host.example", body)).findings}
    assert ("content.callback" in codes) == flagged


@pytest.mark.parametrize("body", ["Pay within 7 days.", "请在3天内完成。", "三日内缴纳。"])
def test_deadlines_create_time_pressure(body):
    assert "content.urgency" in {f.code for f in analyze(_email("Notice", "mail-host.example", body)).findings}


def test_prizes_are_windfalls():
    for body in ("Congratulations, you have won!", "恭喜您抽中大奖。"):
        assert "content.windfall" in {f.code for f in analyze(_email("Promo", "mail-host.example", body)).findings}


@pytest.mark.parametrize("code, body", [
    ("content.off_channel", "Our hiring manager interviews over WhatsApp."),
    ("content.off_channel", "请添加HR微信获取岗位说明。"),
    ("content.remote_access", "Install AnyDesk so we can check your account."),
    ("content.remote_access", "请下载会议软件并开启屏幕共享。"),
    ("content.cold_open", "Sorry to bother you, I think I got the wrong contact."),
    ("content.investment", "I've been earning 25% a month."),
    ("content.investment", "上个月收益达到40%。"),
    ("content.payment", "Please make a payment of $18,900 today."),
    ("content.payment", "A $2.40 handling charge must be paid."),
    ("content.payment", "你先付押金到我账户。"),
    ("content.remote_deal", "我现在在外地工作回不去。"),
    ("content.account_threat", "Renew now or your website will be deleted."),
    ("content.secrecy", "Between you and me for now, please."),
    ("content.secrecy", "调查期间不要和任何人说起此事。"),
])
def test_round_five_signals(code, body):
    assert code in {f.code for f in analyze(_email("Sender", "mail-host.example", body)).findings}


@pytest.mark.parametrize("body", [
    "Your order total was $54.20 including a $5.00 delivery fee.",  # a receipt, not a request
    "Thanks for your payment. You paid $480 on 1 October.",
])
def test_receipts_are_not_payment_requests(body):
    assert "content.payment" not in {f.code for f in analyze(_email("Store", "mail-host.example", body)).findings}


def test_a_parcel_with_a_payment_request_is_suspicious_but_a_delivery_notice_is_not():
    assert analyze(_email("Courier", "mail-host.example", "Your parcel is held. Pay $3.15 to rebook.")).level != "low"
    assert analyze(_email("Courier", "mail-host.example", "Your parcel was delivered today.")).level == "low"


@pytest.mark.parametrize("code, body", [
    ("content.overpayment", "I overpaid you by $900, please refund the extra."),
    ("content.overpayment", "系统多转了一笔，请退还差额。"),
    ("content.money_mule", "Keep 10% as commission and forward the remainder."),
    ("content.money_mule", "你留下5%，剩余的钱转到公司账户。"),
    ("content.legal_threat", "We will refer this to a debt collector."),
    ("content.legal_threat", "我司将依法起诉。"),
    ("content.credentials", "Verify your card details to keep the booking."),
    ("content.account_threat", "The reservation will be cancelled."),
    ("content.account_threat", "否则将影响个人征信。"),
    ("content.payment", "Your parcel is held until import duty of $8.70 is paid."),
    ("content.payment", "Please refund it to my cousin's account."),
])
def test_round_six_signals(code, body):
    assert code in {f.code for f in analyze(_email("Sender", "mail-host.example", body)).findings}


@pytest.mark.parametrize("body, flagged", [
    ("Scratch off the strip and email me photos of the back of the gift cards.", True),
    ("帮我买几张京东E卡，刮开后拍照发给我。", True),
    ("We are collecting supermarket gift cards for families in need.", False),
])
def test_gift_card_code_requests(body, flagged):
    codes = {f.code for f in analyze(_email("Sender", "mail-host.example", body)).findings}
    assert ("content.gift_card_codes" in codes) == flagged


def test_legal_threat_with_a_number_to_call_is_callback_phishing():
    codes = {f.code for f in analyze(_email("Recovery", "mail-host.example",
                                            "Court proceedings will begin. Phone our officer on 02 5550 7788.")).findings}
    assert "content.callback" in codes
    codes = {f.code for f in analyze(_email("Lawyer", "firm.example",
                                            "We will call you after the court hearing on 3 November.")).findings}
    assert "content.callback" not in codes


def test_chat_apps_own_notices_are_not_off_channel_moves():
    codes = {f.code for f in analyze(_email("WhatsApp", "whatsapp.com", "Open WhatsApp to re-register.")).findings}
    assert "content.off_channel" not in codes
    codes = {f.code for f in analyze(_email("Recruiter", "mail-host.example", "Message me on WhatsApp.")).findings}
    assert "content.off_channel" in codes


@pytest.mark.parametrize("body, asks", [
    ("请回复您的邮箱账号和登录密码。", True),
    ("请把短信中的验证码告诉客服。", True),
    ("如非本人操作，请及时修改密码。", False),
    ("不要使用生日作为密码。", False),
])
def test_chinese_password_requests_need_a_request(body, asks):
    codes = {f.code for f in analyze(_email("Notice", "mail-host.example", body)).findings}
    assert ("content.credentials" in codes) == asks
