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
