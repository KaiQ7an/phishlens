import pytest

from phishlens.attachments import classify, encrypted_archive
from phishlens.content import find_signals
from phishlens.message import Attachment


def att(name):
    return Attachment(name, "application/octet-stream", 1, "0" * 64)


@pytest.mark.parametrize("name, code", [
    ("Invoice.pdf.exe", "attachment.double_extension"),
    ("setup.exe", "attachment.executable"),
    ("budget.xlsm", "attachment.macro"),
    ("login.html", "attachment.html"),
    ("files.iso", "attachment.disk_image"),
    ("photos.zip", "attachment.archive"),
])
def test_risky_attachments(name, code):
    assert code in [c for _, c, _ in classify(att(name))]


@pytest.mark.parametrize("name", ["report.pdf", "notes.docx", "README"])
def test_ordinary_attachments(name):
    assert classify(att(name)) == []


def test_macro_documents_are_high_risk():
    assert ("high", "attachment.macro") in [(sev, c) for sev, c, _ in classify(att("PO-5530.xlsm"))]


def test_attached_web_pages_are_high_risk():
    assert ("high", "attachment.html") in [(sev, c) for sev, c, _ in classify(att("voicemail.html"))]


@pytest.mark.parametrize("text", ["The archive password is 4921.", "解压密码：8812"])
def test_archive_sent_with_its_password(text):
    assert encrypted_archive(att("invoice.zip"), text)[1] == "attachment.encrypted_archive"


def test_password_only_matters_for_archives():
    assert encrypted_archive(att("invoice.pdf"), "The password is 4921.") is None
    assert encrypted_archive(att("photos.zip"), "Photos from Saturday attached.") is None


def test_signals_in_english_and_chinese():
    codes = {s.code for s, _ in find_signals("URGENT: verify your account. 请缴纳保证金,切勿告知家人。")}
    assert {"content.urgency", "content.credentials", "content.payment", "content.secrecy"} <= codes


def test_signals_report_matched_phrases():
    (signal, matched), = find_signals("Please pay the processing fee by wire transfer")
    assert signal.code == "content.payment"
    assert set(matched) == {"processing fee", "wire transfer"}


def test_no_signals_in_ordinary_text():
    assert find_signals("The workshop is on Thursday. See you there!") == []


@pytest.mark.parametrize("text", ["请先转发给同学。", "这是我的零用钱。"])
def test_everyday_chinese_is_not_a_payment_request(text):
    assert "content.payment" not in {s.code for s, _ in find_signals(text)}


def test_phrase_and_pattern_matches_are_reported_once():
    (signal, matched), = find_signals("请在24小时内处理")
    assert signal.code == "content.urgency" and matched == ["24小时内"]


@pytest.mark.parametrize("text", [
    "We will never ask for your seed phrase or password.",
    "Support never requests your recovery phrase.",
    "币安员工绝不会向您索要助记词。",
    "We will never ask you to pay with gift cards.",
])
def test_safety_advice_is_not_a_request(text):
    codes = {s.code for s, _ in find_signals(text)}
    assert not codes & {"content.wallet_secret", "content.credentials", "content.payment"}


def test_reassurance_does_not_hide_a_request_in_another_sentence():
    codes = {s.code for s, _ in find_signals(
        "We will never ask for your password. Enter your recovery phrase to finish the check.")}
    assert "content.wallet_secret" in codes


def test_negation_does_not_apply_to_pressure_or_secrecy():
    codes = {s.code for s, _ in find_signals("Never share this with anyone. Do not tell your family.")}
    assert "content.secrecy" in codes


@pytest.mark.parametrize("text, asks", [
    ("Your verification code is 482913. It expires in 10 minutes.", False),
    ("Share your referral code with friends and get $10.", False),
    ("Don't share this verification code with anyone.", False),
    ("Reply with the code we sent to your phone.", True),
    ("Please send us the 6-digit code from the text message.", True),
])
def test_codes_count_only_when_asked_for(text, asks):
    assert ("content.credentials" in {s.code for s, _ in find_signals(text)}) == asks


@pytest.mark.parametrize("text, payment", [
    ("Give a gift card, delivered by email.", False),
    ("Pay with Google Play gift cards today.", True),
    ("请用京东E卡支付罚款。", True),
    ("Payment of $35.00 will be taken on 20 October.", False),
    ("Please make a same-day payment of $18,900.", True),
])
def test_payment_requests_need_a_request(text, payment):
    assert ("content.payment" in {s.code for s, _ in find_signals(text)}) == payment


@pytest.mark.parametrize("text", [
    "Never give your security code to anyone, including our staff.",
    "Do not provide this one-time code to anyone who calls you.",
])
def test_code_safety_warnings_are_not_requests(text):
    assert "content.credentials" not in {s.code for s, _ in find_signals(text)}


def test_secrecy_in_the_same_sentence_does_not_hide_a_code_request():
    codes = {s.code for s, _ in find_signals("Send me the verification code and never tell anyone.")}
    assert "content.credentials" in codes


@pytest.mark.parametrize("text, asks", [
    ("We will send a security code to your phone.", False),
    ("We'll send a one-time code to this address.", False),
    ("Send us the 6-digit code from the text message.", True),
    ("Share your verification code with our agent to unlock the account.", True),
    ("Reply with the code immediately.", True),
])
def test_code_requests_need_the_reader_to_hand_it_over(text, asks):
    assert ("content.credentials" in {s.code for s, _ in find_signals(text)}) == asks


@pytest.mark.parametrize("text, payment", [
    ("Go to my account to see delivery details.", False),
    ("Please refund the extra to my cousin's account.", True),
])
def test_account_wording_needs_a_money_verb(text, payment):
    assert ("content.payment" in {s.code for s, _ in find_signals(text)}) == payment
