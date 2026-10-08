"""Labelled synthetic scenarios for measuring PhishLens.

Every message here is invented for evaluation. Labels and splits were written
before the analyzer was run on them:

* ``dev`` scenarios may guide rule changes.
* ``holdout`` scenarios must never be used to tune rules; they only measure
  whether a change generalises. Do not edit a holdout scenario to make it pass.

A phishing scenario counts as detected when the verdict is suspicious or high.
A legitimate scenario counts as correct only when the verdict is low.
``KNOWN_GAPS`` records expectations the current rules do not meet. The test
suite marks them as strict expected failures, so a rule change that fixes one
must also remove its entry; scenario text and labels stay unchanged.

Attacker-controlled domains use the reserved ``.example`` TLD. Legitimate
senders use real organisations' domains only as fictional senders; none of
these messages were sent by those organisations.
"""

from __future__ import annotations

from dataclasses import dataclass
from email.message import EmailMessage

PASS = "mx.receiver.example; spf=pass smtp.mailfrom={d}; dkim=pass header.d={d}; dmarc=pass header.from={d}"


@dataclass(frozen=True)
class Scenario:
    id: str
    split: str  # dev | holdout
    label: str  # legitimate | phishing
    category: str
    note: str
    raw: bytes


def build(sender: str, subject: str, text: str, *, html: str | None = None, auth: str | None = "pass",
          reply_to: str | None = None, return_path: str | None = None,
          attachments: tuple[tuple[str, str, str, bytes], ...] = ()) -> bytes:
    domain = sender.rsplit("@", 1)[-1].rstrip(">")
    msg = EmailMessage()
    if auth == "pass":
        msg["Authentication-Results"] = PASS.format(d=domain)
    elif auth:
        msg["Authentication-Results"] = auth
    msg["From"] = sender
    msg["To"] = "Student <student@example.edu.au>"
    msg["Subject"] = subject
    msg["Date"] = "Fri, 09 Oct 2026 09:00:00 +1100"
    msg["Message-ID"] = "<scenario@phishlens.test>"
    if reply_to:
        msg["Reply-To"] = reply_to
    if return_path:
        msg["Return-Path"] = return_path
    msg.set_content(text)
    if html:
        msg.add_alternative(html, subtype="html")
    for filename, maintype, subtype, payload in attachments:
        msg.add_attachment(payload, maintype=maintype, subtype=subtype, filename=filename)
    return msg.as_bytes()


FAKE = b"PhishLens evaluation placeholder; not a real document or program.\n"


def _dev_legitimate() -> list[Scenario]:
    s = "legitimate"
    return [
        Scenario("dev/legit/university-library", "dev", s, "institution notice",
                 "Ordinary notice from the real domain with links to its own subdomains.",
                 build("Monash Library <library@monash.edu>", "Library opening hours for the exam period",
                       "Hi,\n\nThe library will open 24 hours during the exam period.\n"
                       "Hours: https://www.monash.edu/library and https://lib.monash.edu/hours\n")),
        Scenario("dev/legit/bank-security-notice", "dev", s, "security notice",
                 "Real bank domain warning about a sign-in; mentions passwords only to say it never asks.",
                 build("CommBank <notifications@commbank.com.au>", "New sign-in to NetBank",
                       "We noticed a new sign-in to NetBank from a new device. If this was you, no action is needed.\n"
                       "We will never ask for your password or verification code by email.\n"
                       "Security tips: https://www.commbank.com.au/security\n")),
        Scenario("dev/legit/requested-password-reset", "dev", s, "account email",
                 "User-requested password reset from a service's own domain.",
                 build("GitHub <noreply@github.com>", "Please reset your password",
                       "We received a request to reset your password. Use this link to reset your password:\n"
                       "https://github.com/password_reset/7f3a9c\n\nIf you did not request this, ignore this email.\n")),
        Scenario("dev/legit/police-from-government", "dev", s, "government notice",
                 "Police mentioned by a real government domain about a public event.",
                 build("Victoria Police <community@police.vic.gov.au>", "Community safety forum, Clayton",
                       "Victoria Police is holding a community safety forum at Clayton on Thursday.\n"
                       "Police officers will share tips on avoiding scams. All welcome.\n")),
        Scenario("dev/legit/zh-student-club-event", "dev", s, "Chinese club notice",
                 "Chinese-language student club event with a casual call to sign up.",
                 build("学生会 <events@cssa.example.org>", "中秋晚会报名开始啦",
                       "大家好！\n\n本周五晚上七点在学生中心举办中秋晚会，有月饼和游戏。\n"
                       "立即报名：https://cssa.example.org/events/mid-autumn\n")),
        Scenario("dev/legit/newsletter-tracked-button", "dev", s, "bulk newsletter",
                 "Mailing-service newsletter with a tracked 'Read more' button and a different bounce domain.",
                 build("Example Society <news@example.org>", "October newsletter",
                       "Our October newsletter is out. Read it online.\n",
                       html='<p>Our October newsletter is out.</p><p><a href="https://example.us13.list-manage.example/'
                            'track/click?u=1&amp;id=2">Read more</a></p>',
                       return_path="<bounce@mail.list-manage.example>")),
        Scenario("dev/legit/newsletter-tracked-url-text", "dev", s, "bulk newsletter",
                 "Mailing-service click tracking where the visible text is the final URL; a common false-positive pattern.",
                 build("Example Society <news@example.org>", "Events this week",
                       "See the events calendar.\n",
                       html='<p>See the events calendar:</p><p><a href="https://example.us13.list-manage.example/'
                            'track/click?u=1&amp;id=3">https://www.example.org/events</a></p>',
                       return_path="<bounce@mail.list-manage.example>")),
        Scenario("dev/legit/calendar-invite", "dev", s, "calendar invite",
                 "Colleague sends a meeting invite as an .ics attachment.",
                 build("Alex Chen <alex.chen@example.org>", "Invitation: project sync, Tuesday 2pm",
                       "Hi, sending a quick invite for our project sync on Tuesday at 2pm.\n",
                       attachments=(("invite.ics", "text", "calendar",
                                     b"BEGIN:VCALENDAR\r\nVERSION:2.0\r\nEND:VCALENDAR\r\n"),))),
        Scenario("dev/legit/shared-document", "dev", s, "document share",
                 "Document-sharing notice from the service's own domain with an 'Open' button.",
                 build("Example Docs <no-reply@docs.example.org>", "Jordan shared 'Week 11 notes' with you",
                       "Jordan shared a document with you.\n",
                       html='<p>Jordan shared a document with you.</p>'
                            '<p><a href="https://docs.example.org/d/91ab">Open</a></p>')),
        Scenario("dev/legit/order-receipt-pdf", "dev", s, "receipt",
                 "Shop receipt with a PDF attachment and a mention of payment.",
                 build("Example Store <orders@shop.example.org>", "Your order receipt #48213",
                       "Thanks for your order. Payment received; your receipt is attached.\n",
                       attachments=(("receipt-48213.pdf", "application", "pdf", FAKE),))),
        Scenario("dev/legit/helpdesk-reply-to-subdomain", "dev", s, "institution notice",
                 "Reply-To points to a subdomain of the sender's own organisation.",
                 build("Example University IT <it@example.edu>", "Planned maintenance on Saturday",
                       "Email will be unavailable from 10pm to midnight on Saturday for maintenance.\n",
                       reply_to="IT Support <support@helpdesk.example.edu>")),
        Scenario("dev/legit/zh-bank-statement", "dev", s, "Chinese bank notice",
                 "Chinese bank statement notice that says it never asks for passwords or codes.",
                 build("示例银行 <service@bank.example.com>", "您的十月账单已生成",
                       "尊敬的客户：\n\n您的十月信用卡账单已生成，请登录网上银行查看。\n"
                       "温馨提示：我们不会通过邮件向您索取密码或验证码。\n")),
    ]


def _dev_phishing() -> list[Scenario]:
    p = "phishing"
    return [
        Scenario("dev/phish/m365-mailbox-full", "dev", p, "credential harvest",
                 "Fake Microsoft 365 storage warning from an attacker domain that passes its own authentication.",
                 build("Microsoft 365 <alerts@m365-mailbox-support.example>", "Your mailbox is full",
                       "Your mailbox storage is full and incoming messages are on hold.\n"
                       "Verify your account within 24 hours to restore delivery: "
                       "https://m365-mailbox-support.example/restore\n")),
        Scenario("dev/phish/parcel-redelivery-fee", "dev", p, "delivery scam",
                 "Australia Post impersonation asking for a small redelivery fee.",
                 build("Australia Post <tracking@auspost-redelivery.example>", "Delivery attempt failed",
                       "We could not deliver your parcel. Pay the $2.99 redelivery fee to reschedule delivery:\n"
                       "https://auspost-redelivery.example/pay\n")),
        Scenario("dev/phish/zh-customs-fee", "dev", p, "Chinese delivery scam",
                 "Chinese DHL impersonation demanding a customs clearance fee.",
                 build("DHL 快递 <service@dhl-cn-express.example>", "您的包裹被海关扣留",
                       "您好，您的包裹因关税未缴被海关扣留。请在24小时内支付清关费，否则包裹将被退回。\n"
                       "支付链接：https://dhl-cn-express.example/pay\n")),
        Scenario("dev/phish/ceo-gift-cards", "dev", p, "business email compromise",
                 "Executive impersonation asking for gift cards in secret, no links.",
                 build("Dr Sam Taylor <sam.taylor.office@mail-host.example>", "Quick favour",
                       "Are you at your desk? I need you to buy six Apple gift cards for a client today.\n"
                       "Keep this confidential until I announce it, and reply with the card codes.\n")),
        Scenario("dev/phish/zh-rental-deposit", "dev", p, "Chinese rental scam",
                 "Overseas 'landlord' wants a deposit wired before any viewing.",
                 build("房东 Linda <linda.rental@mail-host.example>", "关于你咨询的房子",
                       "你好，我目前在海外工作，无法带你看房。请先通过西联汇款支付两周押金，"
                       "收到后我会把钥匙寄给你。\n")),
        Scenario("dev/phish/qr-mfa-reenrol", "dev", p, "QR code phishing",
                 "Asks the reader to scan a QR code to re-enrol MFA; the link is hidden in an image.",
                 build("IT Security <security@campus-it-alerts.example>", "Action needed: re-enrol MFA",
                       "Multi-factor authentication must be re-enrolled this week.\n"
                       "Scan the QR code in the attached image with your phone to verify your account.\n",
                       attachments=(("mfa-qr.png", "image", "png", FAKE),))),
        Scenario("dev/phish/encrypted-zip-invoice", "dev", p, "malware delivery",
                 "Password-protected archive with its password in the same email, a common way to evade scanning.",
                 build("Accounts <billing@vendor-invoices.example>", "Invoice 2026-118",
                       "Please find invoice 2026-118 attached. The archive password is 4921.\n",
                       attachments=(("invoice-2026-118.zip", "application", "zip", FAKE),))),
        Scenario("dev/phish/zh-kidnapping-variant", "dev", p, "Chinese impersonation scam",
                 "Fake police tell the student not to call the police or contact the school.",
                 build("公安局 <case@cn-police-notice.example>", "重要案件通知",
                       "你的家人现在情况紧急。不要报警，也不要联系学校，按我们说的做。\n")),
        Scenario("dev/phish/sharepoint-lookalike", "dev", p, "credential harvest",
                 "Fake SharePoint share notice linking to an attacker login page.",
                 build("Jordan via SharePoint <no-reply@sharepoint-docs.example>", "Jordan shared 'Q4 budget.xlsx'",
                       "Jordan shared a file with you.\n",
                       html='<p>Jordan shared a file with you.</p>'
                            '<p><a href="https://sharepoint-docs.example/login">Open</a></p>')),
        Scenario("dev/phish/voicemail-html", "dev", p, "HTML attachment",
                 "Voicemail lure with an attached web page that would host a fake login.",
                 build("Voicemail <voicemail@pbx-notify.example>", "New voicemail (0:42)",
                       "You have a new voicemail. Open the attached file to listen.\n",
                       attachments=(("voicemail-0042.html", "text", "html",
                                     b"<html><body>placeholder</body></html>"),))),
        Scenario("dev/phish/display-name-address", "dev", p, "sender spoofing",
                 "Display name shows a PayPal address while the real sender is an attacker domain.",
                 build('"service@paypal.com" <alert@pp-secure.example>', "Unusual activity on your account",
                       "We noticed unusual activity. Please review your account.\n")),
        Scenario("dev/phish/bank-details-change", "dev", p, "business email compromise",
                 "Supplier asks to change bank details; replies go to a lookalike of the supplier's domain.",
                 build("Finance Team <finance@supplier.example.org>", "Updated bank details",
                       "Please update our bank details for all future payments. Our new account details are "
                       "attached to this email. This is urgent as the next invoice is due this week.\n",
                       reply_to="Finance Team <finance@supp1ier.example.org>")),
    ]


def _holdout() -> list[Scenario]:
    s, p = "legitimate", "phishing"
    return [
        Scenario("holdout/legit/telco-bill", "holdout", s, "bill",
                 "Telco bill notice paid by direct debit.",
                 build("Telstra <bills@telstra.com.au>", "Your bill is ready",
                       "Your October bill is ready. It will be paid by direct debit on 20 October.\n"
                       "View it at https://www.telstra.com.au/my-account\n")),
        Scenario("holdout/legit/tax-return-processed", "holdout", s, "government notice",
                 "Tax office notice from its real domain.",
                 build("Australian Taxation Office <noreply@ato.gov.au>", "Your tax return has been processed",
                       "Your 2026 tax return has been processed. Your notice of assessment is in myGov.\n")),
        Scenario("holdout/legit/zh-course-registration", "holdout", s, "Chinese institution notice",
                 "Chinese course-registration notice from the university's real domain.",
                 build("Monash 学生服务 <student.services@monash.edu>", "选课系统下周开放",
                       "同学们好：\n\n下学期选课系统将于下周一开放，请登录 Moodle 查看课程安排。\n")),
        Scenario("holdout/legit/ride-receipt", "holdout", s, "receipt",
                 "Ride receipt with a 'View receipt' button.",
                 build("Example Rides <receipts@rides.example.com>", "Your Friday evening trip",
                       "Thanks for riding with us. Total: $18.40.\n",
                       html='<p>Thanks for riding with us. Total: $18.40.</p>'
                            '<p><a href="https://rides.example.com/receipts/5521">View receipt</a></p>')),
        Scenario("holdout/legit/club-personal-reply-to", "holdout", s, "club notice",
                 "Club announcement whose replies go to the organiser's personal address.",
                 build("Chess Club <club@chess.example.org>", "Tournament this Saturday",
                       "Our tournament starts at 10am on Saturday. Reply to register.\n",
                       reply_to="Organiser <organiser.jamie@mail-host.example>")),
        Scenario("holdout/legit/verification-code", "holdout", s, "account email",
                 "Expected two-factor code email telling the reader not to share it.",
                 build("Example App <security@app.example.com>", "Your verification code",
                       "Your verification code is 482913. It expires in 10 minutes. "
                       "Don't share this code with anyone.\n")),
        Scenario("holdout/phish/streaming-payment-failed", "holdout", p, "credential harvest",
                 "Streaming-service billing lure asking to update payment details.",
                 build("Netflix <billing@netflix-account-update.example>", "Payment declined",
                       "Your payment was declined. Update your payment details within 48 hours to keep watching:\n"
                       "https://netflix-account-update.example/billing\n")),
        Scenario("holdout/phish/tax-refund", "holdout", p, "government impersonation",
                 "Tax refund lure asking the reader to confirm identity details.",
                 build("Australian Taxation Office <refunds@ato-refund-portal.example>", "You are eligible for a refund",
                       "You are eligible for a tax refund of $812.40. Confirm your identity and bank account "
                       "to claim it: https://ato-refund-portal.example/claim\n")),
        Scenario("holdout/phish/zh-embassy-document", "holdout", p, "Chinese impersonation scam",
                 "Fake embassy says an important document is waiting and asks for identity details.",
                 build("中国大使馆 <service@embassy-cn-notice.example>", "您有一份重要文件未领取",
                       "您好，您有一份重要文件未领取。请回复本邮件核实您的身份信息。\n")),
        Scenario("holdout/phish/crypto-investment", "holdout", p, "investment scam",
                 "Too-good-to-be-true crypto returns with a deposit request.",
                 build("Wealth Desk <advisor@usdt-yield.example>", "Earn 30% every week",
                       "Our USDT platform pays 30% every week. Deposit at least $500 today to secure your place:\n"
                       "https://usdt-yield.example/deposit\n")),
        Scenario("holdout/phish/macro-invoice", "holdout", p, "malware delivery",
                 "Invoice in a macro-enabled document with instructions to enable content.",
                 build("Accounts Receivable <ar@invoice-centre.example>", "Overdue invoice",
                       "Your invoice is overdue. Open the attached document and click Enable Content to view it.\n",
                       attachments=(("invoice-0931.docm", "application",
                                     "vnd.ms-word.document.macroEnabled.12", FAKE),))),
        Scenario("holdout/phish/social-copyright-appeal", "holdout", p, "account takeover",
                 "Social-media copyright strike threatening suspension within 24 hours.",
                 build("Instagram Support <support@ig-copyright-appeal.example>", "Copyright violation notice",
                       "Your account will be suspended within 24 hours because of a copyright complaint.\n"
                       "Submit an appeal here: https://ig-copyright-appeal.example/appeal\n")),
    ]


SCENARIOS: tuple[Scenario, ...] = tuple(_dev_legitimate() + _dev_phishing() + _holdout())


# Scenario id -> why the current rules miss it. Remove an entry when it is fixed.
KNOWN_GAPS: dict[str, str] = {
    "dev/legit/newsletter-tracked-url-text":
        "Click tracking whose visible text is the final URL reads as an anchor mismatch; only Constant "
        "Contact's documented route is calibrated, deliberately not a general mailing-service allowlist.",
    "dev/phish/zh-customs-fee": "Authority claimed in the display name and customs/delivery fees are not recognised.",
    "dev/phish/zh-rental-deposit": "No signal for an unseen party who wants money before any meeting.",
    "dev/phish/qr-mfa-reenrol": "No signal for QR codes, which move the link out of reach of link checks.",
    "dev/phish/encrypted-zip-invoice": "An archive whose password is in the same email is only scored as an archive.",
    "dev/phish/zh-kidnapping-variant": "Authority in the display name and 'do not call the police' are not recognised.",
    "dev/phish/sharepoint-lookalike": "Microsoft product names such as SharePoint are not tied to the Microsoft brand.",
    "dev/phish/voicemail-html": "A lone HTML attachment scores just below the suspicious threshold.",
    "dev/phish/bank-details-change": "Requests to change bank details are not treated as payment requests.",
    "holdout/phish/tax-refund": "Missed by the baseline rules (holdout: not used for tuning).",
    "holdout/phish/zh-embassy-document": "Missed by the baseline rules (holdout: not used for tuning).",
    "holdout/phish/crypto-investment": "Missed by the baseline rules (holdout: not used for tuning).",
    "holdout/phish/macro-invoice": "Missed by the baseline rules (holdout: not used for tuning).",
    "holdout/phish/social-copyright-appeal": "Missed by the baseline rules (holdout: not used for tuning).",
}
