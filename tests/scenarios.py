"""Labelled synthetic scenarios for measuring PhishLens.

Every message here is invented for evaluation. Labels and splits were written
before the analyzer was run on them:

* ``dev`` scenarios may guide rule changes.
* ``holdout`` to ``holdout7`` scenarios must never be used to tune rules;
  they only measure whether a change generalises. Do not edit a holdout
  scenario to make it pass. Each holdout's missed categories shaped the
  next round of dev scenarios, so the newest set, ``holdout7``, is the
  current unseen measure.

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
    split: str  # one of SPLITS
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


SPLITS = ("dev", "holdout", "holdout2", "holdout3", "holdout4", "holdout5", "holdout6", "holdout7")

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


def _dev_round_four() -> list[Scenario]:
    """Added 2026-10-09. Categories follow the holdout3 misses (callback
    phishing, fines and fees, prizes, wallet secrets, HR lures, charity and
    immigration scams); the text is written fresh. Legitimate messages probe
    false alarms, including existing authority rules on university mail."""
    s, p = "legitimate", "phishing"
    return [
        Scenario("dev/phish/callback-tech-support", "dev", p, "callback phishing",
                 "Fake tech-support plan renewal that asks the reader to phone to cancel.",
                 build("Geek Support Renewals <orders@tech-plan-billing.example>", "Your plan renewal receipt",
                       "Thank you for renewing your Total Tech Protection plan. $289.99 has been charged to "
                       "your account. To cancel and request a refund, call 1-800-555-0199.\n")),
        Scenario("dev/phish/zh-callback-renewal", "dev", p, "Chinese callback phishing",
                 "Fake membership auto-renewal that asks the reader to phone to cancel.",
                 build("会员服务中心 <vip@member-renew-center.example>", "会员自动续费通知",
                       "您的年度会员将于今日自动续费899元。如需取消，请立即致电客服 400-800-1234 办理。\n")),
        Scenario("dev/phish/parking-infringement", "dev", p, "payment lure",
                 "Fake parking infringement with a rising penalty and an unrelated payment host.",
                 build("Infringement Notices <fines@parking-penalty-notice.example>", "Infringement notice 4410982",
                       "An unpaid parking fine of $120 is recorded against your vehicle. Pay within 7 days "
                       "or a late fee will be added.\n",
                       html='<p><a href="https://parking-penalty-notice.example/pay">Pay fine</a></p>')),
        Scenario("dev/phish/zh-prize-postage", "dev", p, "Chinese prize scam",
                 "Prize notice that only needs a small postage fee.",
                 build("周年庆活动组 <gift@anniversary-gift.example>", "恭喜您获得幸运大奖",
                       "恭喜您在周年庆活动中抽中iPhone一台！只需支付邮费9.9元即可免费领取，"
                       "名额有限，先到先得。\n")),
        Scenario("dev/phish/seed-phrase-upgrade", "dev", p, "crypto theft",
                 "Wallet 'security upgrade' asking the reader to confirm their seed phrase.",
                 build("Wallet Security <security@wallet-upgrade-team.example>", "Mandatory wallet security upgrade",
                       "A mandatory security upgrade is required for your wallet. Confirm your seed phrase "
                       "on the upgrade page to keep access to your funds.\n",
                       html='<p><a href="https://wallet-upgrade-team.example/upgrade">Upgrade wallet</a></p>')),
        Scenario("dev/phish/bonus-letter-login", "dev", p, "credential harvest",
                 "Performance bonus letter behind a login page on an unrelated host.",
                 build("People & Culture <people@bonus-letters-portal.example>", "Q4 performance bonus letter",
                       "Your Q4 performance bonus letter is ready. Log in to view your bonus amount.\n",
                       html='<p><a href="https://bonus-letters-portal.example/login">View bonus letter</a></p>')),
        Scenario("dev/phish/charity-gift-cards", "dev", p, "charity scam",
                 "Hospital appeal that asks for donations as gift cards.",
                 build("Children's Hospital Appeal <appeal@kids-hospital-help.example>", "Can you help a sick child?",
                       "Our appeal closes tonight. The fastest way to donate is to buy gift cards and reply "
                       "with the card numbers so we can redeem them for the families.\n")),
        Scenario("dev/phish/immigration-penalty", "dev", p, "government impersonation",
                 "Fake immigration notice demanding a penalty and passport copy.",
                 build("Immigration Compliance <compliance@visa-status-review.example>", "Visa compliance review",
                       "The Department of Home Affairs has found a problem with your visa. Pay the "
                       "compliance penalty of $750 and upload a copy of your passport within 48 hours.\n")),
        Scenario("dev/legit/uni-safety-police", "dev", s, "university notice",
                 "University security notice that tells students to contact the police.",
                 build("Monash Security <security@monash.edu>", "Campus safety reminder",
                       "If you see suspicious behaviour on campus, contact Monash Security or Victoria Police "
                       "on 000. Scam calls claiming to be from the police are common; hang up and call back "
                       "on an official number.\n")),
        Scenario("dev/legit/uni-visa-advice", "dev", s, "university notice",
                 "International office reminder about visa conditions.",
                 build("Monash International <international@monash.edu>", "Keeping your visa conditions",
                       "The Department of Home Affairs requires student visa holders to maintain enrolment. "
                       "Contact us if you plan to reduce your study load.\n")),
        Scenario("dev/legit/council-parking-fine", "dev", s, "government notice",
                 "Real council parking infringement from a government domain.",
                 build("City of Melbourne <parking@melbourne.vic.gov.au>", "Infringement notice 9921004",
                       "An infringement notice of $99 has been issued for your vehicle. Pay within 21 days "
                       "at melbourne.vic.gov.au/pay or request a review.\n")),
        Scenario("dev/legit/bank-alert-phone", "dev", s, "bank notice",
                 "Real bank transaction alert with the bank's phone number.",
                 build("CommBank <alerts@commbank.com.au>", "Card transaction alert",
                       "A $64.20 transaction was made on your card ending 1234. If you didn't make this "
                       "transaction, call us on 13 22 21.\n")),
        Scenario("dev/legit/zh-icloud-renewal", "dev", s, "Chinese subscription notice",
                 "Real subscription renewal notice.",
                 build("Apple <no_reply@email.apple.com>", "您的订阅即将续订",
                       "您的 iCloud+ 订阅将于11月1日自动续订，费用为每月6元。如需取消，可在设置中管理订阅。\n")),
        Scenario("dev/legit/staff-bonus-portal", "dev", s, "workplace notice",
                 "Real HR notice telling staff to sign in to the staff portal.",
                 build("Monash HR <hr@monash.edu>", "Your remuneration letter",
                       "Your 2027 remuneration letter is available. Sign in to the staff portal to view it.\n")),
        Scenario("dev/legit/photo-competition-winner", "dev", s, "club notice",
                 "Student club telling a member they won a competition, with no payment.",
                 build("Monash Photography Club <photoclub@monash.edu>", "You won!",
                       "Congratulations, you have won first prize in our photo competition! Collect your "
                       "prize from the club room on Wednesday.\n")),
    ]


def _dev_round_five() -> list[Scenario]:
    """Added 2026-10-09. Categories follow the holdout4 misses; each phishing
    category has two independently worded versions (-a/-b) so rules must
    capture the intent rather than one phrasing. Legitimate messages use the
    same intents (installing software, chat apps, payments) for real reasons."""
    s, p = "legitimate", "phishing"
    return [
        Scenario("dev/phish/zh-police-isolation-a", "dev", p, "Chinese impersonation scam",
                 "Fake prosecutor asks for a private video call in a quiet room.",
                 build("检察院办案人员 <office@jcy-case-handling.example>", "案件协查通知",
                       "你涉嫌参与一起跨境洗钱案，现需远程协助调查。请找一个没有人的房间，"
                       "通过视频和我们连线，调查期间不要和任何人说起此事。\n")),
        Scenario("dev/phish/zh-police-isolation-b", "dev", p, "Chinese impersonation scam",
                 "Fake officer asks for screen sharing and silence.",
                 build("王警官 <wang.jg@case-verify-office.example>", "身份核实",
                       "您名下的银行卡被犯罪团伙使用，需要核实资金来源。请下载会议软件并开启屏幕共享，"
                       "核实结束前不要声张。\n")),
        Scenario("dev/phish/parcel-fee-a", "dev", p, "delivery scam",
                 "Parcel held for a small handling charge.",
                 build("Courier Desk <help@courier-hold-desk.example>", "Parcel on hold",
                       "Your parcel is on hold at our depot. A $2.40 handling charge must be paid before "
                       "it can be released.\n",
                       html='<p><a href="https://courier-hold-desk.example/release">Release parcel</a></p>')),
        Scenario("dev/phish/parcel-fee-b", "dev", p, "delivery scam",
                 "Missed delivery that needs a rebooking payment.",
                 build("Delivery Notice <notice@rebook-my-parcel.example>", "Missed delivery attempt",
                       "Our driver could not reach you. To schedule a new delivery, confirm your details "
                       "and pay $3.15 online.\n",
                       html='<p><a href="https://rebook-my-parcel.example/schedule">Reschedule</a></p>')),
        Scenario("dev/phish/exec-payment-a", "dev", p, "business email compromise",
                 "Executive asks for a discreet same-day payment.",
                 build("Laura Bennett <laura.bennett.exec@gmail.com>", "Need this done today",
                       "Please make a same-day payment of $18,900 to the supplier below. This is sensitive, "
                       "so don't discuss it with anyone else in the team.\n")),
        Scenario("dev/phish/exec-payment-b", "dev", p, "business email compromise",
                 "Director asks for a quiet transfer before an acquisition is announced.",
                 build("Mark Ellis <director.mark.ellis@outlook.com>", "Acquisition - private",
                       "We're closing an acquisition. I need you to send $42,000 to our legal adviser's "
                       "account this morning. Between you and me for now, please.\n")),
        Scenario("dev/phish/zh-rental-away-a", "dev", p, "Chinese rental scam",
                 "Landlord working out of town wants the deposit first.",
                 build("刘女士 <liu.landlord@mail-host.example>", "关于租房",
                       "房子在的，我现在在外地工作回不去，你先付两个月押金到我账户，我把钥匙快递给你。\n")),
        Scenario("dev/phish/zh-rental-away-b", "dev", p, "Chinese rental scam",
                 "Landlord abroad asks for a deposit before handing over the keys through a friend.",
                 build("Mr Zhou <zhou.house@mail-host.example>", "公寓出租",
                       "我人不在国内，公寓交给朋友打理。你把定金打过来，朋友就把钥匙交给你，直接入住。\n")),
        Scenario("dev/phish/trading-cold-open-a", "dev", p, "investment scam",
                 "'Wrong number' opener that turns to a forex platform with large returns.",
                 build("Grace Wong <grace.w.invest@mail-host.example>", "Is this Kevin?",
                       "Hi Kevin, is this still your email? Oh sorry, wrong person! Since we're chatting, "
                       "I've been earning 25% a month on a forex platform my mentor runs.\n")),
        Scenario("dev/phish/trading-cold-open-b", "dev", p, "investment scam",
                 "Stranger who 'got the wrong contact' offers to teach futures trading.",
                 build("Vivian Ho <vivian.ho.mkts@mail-host.example>", "Sorry to bother you",
                       "Sorry to bother you, I think I got the wrong contact. If you're interested, my "
                       "futures account made 60% profit this quarter and I can teach you.\n")),
        Scenario("dev/phish/service-expiry-a", "dev", p, "renewal scam",
                 "Website hosting 'expires today' and must be renewed through an unrelated site.",
                 build("Hosting Billing <billing@host-renewal-desk.example>", "Hosting expires today",
                       "Your website hosting expires today. Renew now or your website and email will be "
                       "deleted.\n",
                       html='<p><a href="https://host-renewal-desk.example/renew">Renew hosting</a></p>')),
        Scenario("dev/phish/service-expiry-b", "dev", p, "renewal scam",
                 "Cloud storage plan about to lapse, with photo loss threatened.",
                 build("Cloud Storage <storage@photo-cloud-plans.example>", "Final reminder: storage plan",
                       "Your storage plan has lapsed. Update your payment information to avoid losing your "
                       "photos and files.\n",
                       html='<p><a href="https://photo-cloud-plans.example/billing">Update payment</a></p>')),
        Scenario("dev/phish/chat-app-recruiter-a", "dev", p, "job scam",
                 "Recruiter moves the 'interview' to WhatsApp.",
                 build("Recruiting Team <talent@flexi-roles-hiring.example>", "You've been shortlisted",
                       "Thanks for your interest. Our hiring manager conducts interviews over WhatsApp. "
                       "Add her number to arrange your interview.\n")),
        Scenario("dev/phish/chat-app-recruiter-b", "dev", p, "job scam",
                 "Chinese job lead asks to add a WeChat contact to receive tasks.",
                 build("招聘专员 <zhaopin@part-time-hr.example>", "线上职位邀请",
                       "您好，您的简历已通过初筛。请添加HR微信，获取岗位说明和入职安排。\n")),
        Scenario("dev/legit/it-install-mfa-app", "dev", s, "IT notice",
                 "Real IT notice asking staff to install the official authenticator app.",
                 build("Monash eSolutions <servicedesk@monash.edu>", "Set up Okta Verify",
                       "Please download and install the Okta Verify app from the App Store or Google Play "
                       "before 1 November to keep signing in.\n")),
        Scenario("dev/legit/zh-club-wechat-group", "dev", s, "Chinese club notice",
                 "Club invites new members to its WeChat group.",
                 build("中国学联 <cssa@monash.edu>", "欢迎加入新生群",
                       "欢迎新同学！请添加学联微信小助手，拉你进新生交流群，获取活动通知。\n")),
        Scenario("dev/legit/registrar-renewal", "dev", s, "renewal notice",
                 "Real domain registrar renewal reminder.",
                 build("Namecheap <support@namecheap.com>", "Domain renewal reminder",
                       "Your domain kaiq7an.dev expires in 30 days. Auto-renew is on, so no action is "
                       "needed.\n")),
        Scenario("dev/legit/finance-invoice-approval", "dev", s, "workplace request",
                 "Real finance request to approve a supplier invoice in the usual system.",
                 build("Monash Finance <finance@monash.edu>", "Invoice awaiting your approval",
                       "Invoice 55120 from Officeworks ($1,240.00) is awaiting your approval in the finance "
                       "system. Please review it by Friday.\n")),
        Scenario("dev/legit/agency-rental-deposit", "dev", s, "property notice",
                 "Real agency explaining the bond after a viewing and signed lease.",
                 build("Ray White Clayton <rentals.clayton@raywhite.com>", "Next steps for your lease",
                       "Thanks for signing the lease. Please pay the bond of $1,920 through the RTBA portal; "
                       "keys can be collected from our office on the start date.\n")),
        Scenario("dev/legit/conference-whatsapp", "dev", s, "event",
                 "Conference inviting attendees to an optional WhatsApp community.",
                 build("UniHack <team@unihack.net>", "UniHack 2026: you're in!",
                       "You're registered for UniHack 2026. Join our WhatsApp community for updates on the "
                       "day. See you there!\n")),
        Scenario("dev/legit/zh-friend-wrong-person", "dev", s, "personal",
                 "Friend apologising for a message sent to the wrong person.",
                 build("Kevin Li <kevin.li.92@gmail.com>", "发错了",
                       "不好意思，刚才那封邮件发错人了，请忽略。周末见！\n")),
    ]


def _dev_round_six() -> list[Scenario]:
    """Added 2026-10-09. Categories follow the holdout5 misses; two
    independently worded versions per category (-a/-b), plus legitimate
    messages about duties, refunds, bookings, loans and legal matters."""
    s, p = "legitimate", "phishing"
    return [
        Scenario("dev/phish/overpayment-a", "dev", p, "refund scam",
                 "Claims a refund was sent twice and asks for one back.",
                 build("Customer Accounts <accounts@billing-correction.example>", "Duplicate refund issued",
                       "Our system issued your $650 refund twice by mistake. Please send back the duplicate "
                       "amount of $650 by bank transfer, or we will refer the matter to a debt collector.\n")),
        Scenario("dev/phish/overpayment-b", "dev", p, "refund scam",
                 "Seller 'overpaid' the reader and wants the excess returned.",
                 build("Marketplace Buyer <buyer.jason@mail-host.example>", "Overpaid for the bike",
                       "Hi, I accidentally overpaid you by $900 for the bike. Can you refund the extra to my "
                       "cousin's account today? My bank says it will take weeks otherwise.\n")),
        Scenario("dev/phish/money-mule-a", "dev", p, "money mule",
                 "Payment processing 'job' that receives funds and forwards most of them.",
                 build("Payments Team <jobs@intl-payment-agents.example>", "Payment agent position",
                       "As our local payment agent you will receive customer payments into your account. "
                       "Keep 10% as your commission and forward the remainder to our supplier within a day.\n")),
        Scenario("dev/phish/money-mule-b", "dev", p, "money mule",
                 "Chinese 'part-time' job receiving and passing on money.",
                 build("跨境结算 <hr@cross-border-settle.example>", "兼职代收款",
                       "招聘兼职代收款人员：客户货款会先打到你的银行卡，你留下5%作为报酬，"
                       "剩余的钱当天转到公司指定账户即可。\n")),
        Scenario("dev/phish/gift-card-photos-a", "dev", p, "impersonation",
                 "Free-mail 'principal' wants gift cards with photos of the back.",
                 build("Principal Helen Ward <principal.h.ward@gmail.com>", "Need your help",
                       "I'm tied up in meetings. Please pick up five $100 iTunes gift cards for staff awards, "
                       "scratch off the silver strip and email me photos of the back of each card.\n")),
        Scenario("dev/phish/gift-card-photos-b", "dev", p, "Chinese impersonation",
                 "Free-mail 'manager' wants gift cards and pictures of the codes.",
                 build("张总 <zhang.manager.office@163.com>", "帮我办点事",
                       "我在开会不方便接电话。帮我买几张京东E卡给客户，刮开后拍照发给我，回头报销。\n")),
        Scenario("dev/phish/legal-callback-a", "dev", p, "callback phishing",
                 "Court action threat with a phone number to settle.",
                 build("Recovery Unit <notice@court-action-desk.example>", "Court proceedings to commence",
                       "Court proceedings will begin against you for an unpaid debt unless you settle it. "
                       "Phone our case officer on 02 5550 7788 before 5pm.\n")),
        Scenario("dev/phish/legal-callback-b", "dev", p, "Chinese callback phishing",
                 "Lawsuit threat with a number to call.",
                 build("法务部 <fawu@debt-legal-notice.example>", "起诉通知",
                       "您有一笔欠款逾期未还，我司将依法向法院起诉。如有异议，请于今日致电 021-5550-3366。\n")),
        Scenario("dev/phish/booking-card-a", "dev", p, "booking scam",
                 "Hotel booking needs card details verified or it will be cancelled.",
                 build("Reservations Team <guest@stay-verify-desk.example>", "Your reservation is at risk",
                       "We could not charge the card for your upcoming stay. Verify your card details "
                       "within 24 hours or the reservation will be cancelled.\n",
                       html='<p><a href="https://stay-verify-desk.example/card">Verify card</a></p>')),
        Scenario("dev/phish/booking-card-b", "dev", p, "booking scam",
                 "Airline ticket needs card details updated to avoid cancellation.",
                 build("Ticketing <tickets@flight-confirm-centre.example>", "Payment failed for your ticket",
                       "Payment for ticket 0816-22 did not go through. Update your card details today or the "
                       "ticket will be canceled.\n",
                       html='<p><a href="https://flight-confirm-centre.example/pay">Update card</a></p>')),
        Scenario("dev/phish/zh-credit-threat-a", "dev", p, "Chinese credit scam",
                 "Fake platform says an old loan account affects credit unless funds are moved.",
                 build("征信服务中心 <help@credit-repair-cn.example>", "征信异常提醒",
                       "您名下有未注销的网贷账户，将影响个人征信。请按客服指引把资金转入监管账户，"
                       "核验后原路退回。\n")),
        Scenario("dev/phish/zh-credit-threat-b", "dev", p, "Chinese credit scam",
                 "Fake app support says a student account must be closed to protect credit.",
                 build("平台客服 <kefu@campus-loan-help.example>", "学生账户关闭通知",
                       "因政策调整，学生用户账户需要关闭，否则征信会留下不良记录。"
                       "关闭前需将额度内的钱转到我们的安全账户进行清零。\n")),
        Scenario("dev/phish/customs-duty-a", "dev", p, "delivery scam",
                 "Parcel held until import duty is paid on a linked page.",
                 build("Customs Clearance <clearance@import-duty-pay.example>", "Import duty payable",
                       "Your parcel from overseas is being held until import duty of $8.70 is paid.\n",
                       html='<p><a href="https://import-duty-pay.example/duty">Pay duty</a></p>')),
        Scenario("dev/phish/customs-duty-b", "dev", p, "Chinese delivery scam",
                 "Chinese parcel notice that requires paying tax before release.",
                 build("跨境物流 <notice@global-parcel-tax.example>", "包裹待缴税",
                       "您的海外包裹需缴纳进口税费后才能放行，请尽快在页面完成支付。\n"
                       "https://global-parcel-tax.example/tax\n")),
        Scenario("dev/legit/abf-duty-notice", "dev", s, "government notice",
                 "Real border agency import duty notice.",
                 build("Australian Border Force <noreply@abf.gov.au>", "Import declaration lodged",
                       "An import declaration has been lodged for your shipment. Duty and GST will be "
                       "collected by your courier on delivery.\n")),
        Scenario("dev/legit/bank-refund-reversal", "dev", s, "bank notice",
                 "Real bank telling a customer a duplicate refund was reversed automatically.",
                 build("CommBank <notifications@commbank.com.au>", "Refund correction",
                       "A duplicate refund of $650 was credited to your account in error and has been "
                       "reversed. No action is needed.\n")),
        Scenario("dev/legit/hotel-card-update", "dev", s, "booking",
                 "Real booking platform asking to update a card inside its own site.",
                 build("Booking.com <noreply@booking.com>", "Update your payment details",
                       "The property couldn't charge your card. Update your card details in your Booking.com "
                       "account to keep your reservation.\n",
                       html='<p><a href="https://secure.booking.com/mytrips.html">Manage booking</a></p>')),
        Scenario("dev/legit/help-debt-statement", "dev", s, "government notice",
                 "Real government student loan statement.",
                 build("Study Assist <noreply@studyassist.gov.au>", "Your HELP debt statement",
                       "Your HELP debt statement is available in myGov. Repayments are made through the "
                       "tax system; no payment is needed now.\n")),
        Scenario("dev/legit/church-gift-card-drive", "dev", s, "community notice",
                 "Real community gift card drive with drop-off.",
                 build("St Mary's Parish <office@stmarysclayton.org.au>", "Christmas gift card drive",
                       "This year we are collecting supermarket gift cards for families in need. Please "
                       "drop them in the box at the parish office.\n")),
        Scenario("dev/legit/legal-firm-update", "dev", s, "legal notice",
                 "Real law firm update to its own client.",
                 build("Slater and Gordon <updates@slatergordon.com.au>", "Update on your matter",
                       "Your lawyer has filed the documents with the court. We will call you after the "
                       "hearing on 3 November.\n")),
        Scenario("dev/legit/agent-commission", "dev", s, "workplace notice",
                 "Real sales commission notice.",
                 build("Monash Bookshop <payroll@monash.edu>", "Commission paid",
                       "Your commission of $120 for September has been paid with your salary.\n")),
    ]


def _dev_round_seven() -> list[Scenario]:
    """Added 2026-10-09 after holdout6's false alarm. Security advice that says
    what a service will never ask for, in two wordings and Chinese, plus a
    phishing message that uses the same reassurance before asking anyway."""
    s, p = "legitimate", "phishing"
    return [
        Scenario("dev/legit/wallet-never-request", "dev", s, "security notice",
                 "Wallet provider reminds users that support never requests recovery phrases.",
                 build("MetaMask <support@metamask.io>", "Stay safe from support scams",
                       "Reminder: our support team will never request your recovery phrase or private key. "
                       "Anyone who asks for it is trying to steal your funds.\n")),
        Scenario("dev/legit/zh-exchange-never-ask", "dev", s, "Chinese security notice",
                 "Exchange reminds users in Chinese that staff never ask for seed words.",
                 build("币安 <do-not-reply@binance.com>", "安全提醒",
                       "币安员工绝不会向您索要助记词、私钥或验证码，请勿向任何人透露。\n")),
        Scenario("dev/legit/bank-never-gift-cards", "dev", s, "security notice",
                 "Bank explains it never asks customers to pay with gift cards or move money.",
                 build("Westpac <notifications@westpac.com.au>", "How to spot a scam",
                       "We will never ask you to pay with gift cards, buy bitcoin or transfer money to a "
                       "'safe account'. If someone does, hang up.\n")),
        Scenario("dev/legit/it-never-remote", "dev", s, "IT notice",
                 "IT warns that it never asks callers to install remote access tools.",
                 build("Monash eSolutions <servicedesk@monash.edu>", "Beware of fake IT calls",
                       "The service desk will never ask you to install AnyDesk or TeamViewer or to share your "
                       "screen with an unexpected caller.\n")),
        Scenario("dev/phish/reassure-then-ask", "dev", p, "crypto theft",
                 "Reassures that it never asks for passwords, then asks for the recovery phrase.",
                 build("Wallet Support <help@wallet-support-desk.example>", "Complete your security check",
                       "We will never ask for your password by email. To finish the security check, enter "
                       "your recovery phrase on the verification page.\n",
                       html='<p><a href="https://wallet-support-desk.example/check">Verify wallet</a></p>')),
    ]


def _dev_round_eight() -> list[Scenario]:
    """Added 2026-10-09 after holdout7's false alarms: chat apps' own notices,
    which name the app, and Chinese advice to change a password, which names
    the password without asking for it. Two wordings each, plus phishing that
    does ask for a password or code in Chinese."""
    s, p = "legitimate", "phishing"
    return [
        Scenario("dev/legit/whatsapp-own-notice", "dev", s, "security notice",
                 "Chat app's own email about a new registration.",
                 build("WhatsApp <noreply@whatsapp.com>", "Your WhatsApp account was registered on a new phone",
                       "Your WhatsApp account was registered on a new phone. If this wasn't you, open "
                       "WhatsApp and re-register your number immediately.\n")),
        Scenario("dev/legit/telegram-own-notice", "dev", s, "security notice",
                 "Chat app's own email about a login.",
                 build("Telegram <noreply@telegram.org>", "New login to Telegram",
                       "We detected a login to your Telegram account from a new device. If this was not you, "
                       "terminate the session in Telegram settings.\n")),
        Scenario("dev/legit/zh-qq-mail-security", "dev", s, "Chinese security notice",
                 "Mail provider advising a password change after an unusual login.",
                 build("QQ邮箱 <security@qq.com>", "异地登录提醒",
                       "您的QQ邮箱于今日在异地登录。如非本人操作，请及时修改密码并开启二次验证。\n")),
        Scenario("dev/legit/zh-bank-password-advice", "dev", s, "Chinese security notice",
                 "Bank advising customers to change passwords regularly.",
                 build("中国工商银行 <service@icbc.com.cn>", "账户安全小贴士",
                       "建议您定期更换网上银行登录密码，不要使用生日或手机号作为密码。\n")),
        Scenario("dev/phish/zh-ask-password-a", "dev", p, "Chinese credential theft",
                 "Fake mailbox upgrade asking the reader to reply with their password.",
                 build("邮箱管理员 <admin@mail-upgrade-notice.example>", "邮箱升级通知",
                       "系统将于今晚升级邮箱，为避免数据丢失，请回复您的邮箱账号和登录密码，以便我们为您迁移。\n")),
        Scenario("dev/phish/zh-ask-code-b", "dev", p, "Chinese account takeover",
                 "Fake customer service asking the reader to read out an SMS code.",
                 build("平台客服 <kefu@account-unlock-help.example>", "账户解冻",
                       "您的账户因异常被冻结。我们已向您的手机发送一条短信，请把短信中的验证码告诉客服，"
                       "完成身份核验后即可解冻。\n")),
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


def _dev_round_two() -> list[Scenario]:
    """Added 2026-10-09. The categories follow the round-one holdout misses, but
    the text is written fresh, without reusing holdout wording. Legitimate
    messages here probe likely false alarms from rules for those categories."""
    s, p = "legitimate", "phishing"
    return [
        Scenario("dev/phish/tax-refund-bank-details", "dev", p, "government impersonation",
                 "Fake tax office offers a refund in exchange for bank details.",
                 build("Australian Taxation Office <refunds@ato-refund-centre.example>",
                       "You are eligible for a tax refund",
                       "Our records show you are owed a refund of $812.40 for the 2025-26 income year.\n"
                       "To receive it, confirm your bank details through the secure form within 3 days.\n",
                       html='<p>You are owed a refund of $812.40.</p>'
                            '<p><a href="https://ato-refund-centre.example/claim">Claim your refund</a></p>')),
        Scenario("dev/phish/zh-tax-refund", "dev", p, "Chinese government impersonation",
                 "Fake tax bureau refund asking for a bank card number.",
                 build("国家税务总局 <tuishui@tax-refund-cn.example>", "个人所得税退税待领取",
                       "您有一笔个人所得税退税 1,280 元尚未领取。请点击链接填写银行卡号和预留手机号，"
                       "逾期将视为自动放弃。\nhttps://tax-refund-cn.example/lingqu\n")),
        Scenario("dev/phish/crypto-guaranteed-returns", "dev", p, "investment scam",
                 "Promises guaranteed monthly returns on a crypto deposit.",
                 build("Ethan Brooks <ethan@apex-crypto-capital.example>", "Your spot in our trading group",
                       "Our AI trading platform delivers guaranteed returns of 30% per month.\n"
                       "Start with a minimum deposit of 500 USDT and withdraw profits any time.\n",
                       html='<p>Guaranteed returns of 30% per month.</p>'
                            '<p><a href="https://apex-crypto-capital.example/join">Open your account</a></p>')),
        Scenario("dev/phish/zh-investment-group", "dev", p, "Chinese investment scam",
                 "Invitation to a 'mentor' stock group promising risk-free profits.",
                 build("王老师 <mentor.wang@stock-vip-club.example>", "邀请您加入VIP投资交流群",
                       "本群由资深导师带单，稳赚不赔，日收益3%以上。名额有限，"
                       "添加助理微信后转入保证金即可开通。\n")),
        Scenario("dev/phish/docm-enable-content", "dev", p, "malware delivery",
                 "Remittance advice in a macro document that tells the reader to enable content.",
                 build("Accounts Payable <ap@remit-advice.example>", "Remittance advice 8841",
                       "Please see the attached remittance advice. If the document appears blank, "
                       "click Enable Content to view it.\n",
                       attachments=(("remittance-8841.docm", "application", "vnd.ms-word.document.macroEnabled.12", FAKE),))),
        Scenario("dev/phish/xlsm-purchase-order", "dev", p, "malware delivery",
                 "Purchase order in a macro-enabled workbook from an unknown buyer.",
                 build("Procurement <orders@global-trade-buyers.example>", "New purchase order PO-5530",
                       "Kindly review the attached purchase order and confirm the quantities and price.\n",
                       attachments=(("PO-5530.xlsm", "application", "vnd.ms-excel.sheet.macroEnabled.12", FAKE),))),
        Scenario("dev/phish/facebook-page-violation", "dev", p, "account threat",
                 "Fake Meta notice says the page will be disabled for copyright infringement unless appealed.",
                 build("Meta Support <support@page-review-center.example>", "Your page has been scheduled for deletion",
                       "We received a report of copyright infringement on your Facebook page. "
                       "If you believe this is a mistake, submit an appeal or the page will be disabled.\n",
                       html='<p>Copyright infringement reported on your page.</p>'
                            '<p><a href="https://page-review-center.example/appeal">Submit an appeal</a></p>')),
        Scenario("dev/phish/instagram-badge-lookalike", "dev", p, "account threat",
                 "Offers a verified badge through a domain using the Instagram name.",
                 build("Instagram <badge@instagram-verify-team.example>", "Your account is eligible for a verified badge",
                       "Your account meets the requirements for a verified badge. "
                       "Confirm your login details to complete verification.\n",
                       html='<p><a href="https://instagram-verify-team.example/badge">Get verified</a></p>')),
        Scenario("dev/legit/ato-return-processed", "dev", s, "government notice",
                 "Real tax office domain confirming a refund to the nominated account.",
                 build("Australian Taxation Office <noreply@ato.gov.au>", "Your tax return has been processed",
                       "Your 2025-26 tax return has been processed. Your refund will be paid to your "
                       "nominated bank account. Sign in to myGov to view your notice of assessment.\n")),
        Scenario("dev/legit/payroll-bank-details", "dev", s, "workplace notice",
                 "Employer reminds staff to keep their own bank details current in the HR system.",
                 build("Payroll <payroll@monash.edu>", "End-of-year payroll reminder",
                       "Please check that your bank details and tax file number declaration are up to date "
                       "in the staff portal before 30 November. Payroll will never ask for them by email.\n")),
        Scenario("dev/legit/event-qr-check-in", "dev", s, "event",
                 "Event check-in by scanning a QR code at the venue.",
                 build("Monash Careers <careers@monash.edu>", "Careers fair: how to check in",
                       "On the day, scan the QR code at the entrance to check in and collect your name badge.\n")),
        Scenario("dev/legit/archive-password-separately", "dev", s, "workplace file",
                 "Encrypted archive whose password is sent through another channel.",
                 build("Priya Nair <priya.nair@monash.edu>", "Survey data for the group project",
                       "Hi, the survey data is attached as a zip. I'll text you the password separately.\n",
                       attachments=(("survey-data.zip", "application", "zip", FAKE),))),
        Scenario("dev/legit/broker-monthly-statement", "dev", s, "financial statement",
                 "Real brokerage monthly statement mentioning returns and deposits.",
                 build("CommSec <statements@commsec.com.au>", "Your September statement is ready",
                       "Your monthly statement is ready. It shows your portfolio returns, deposits and "
                       "withdrawals for September. Past performance is not a reliable indicator of future returns.\n")),
        Scenario("dev/legit/youtube-copyright-claim", "dev", s, "platform notice",
                 "Genuine platform notice of a copyright claim with an appeal option.",
                 build("YouTube <no-reply@youtube.com>", "Copyright claim on your video",
                       "A copyright claim was made on your video by the owner of a song it contains. "
                       "Your video is still available. You can dispute the claim in YouTube Studio.\n")),
        Scenario("dev/legit/instagram-login-alert", "dev", s, "security notice",
                 "Genuine sign-in alert from the platform's own mail domain.",
                 build("Instagram <security@mail.instagram.com>", "New login to your account",
                       "We noticed a new login from Chrome on Mac near Melbourne. If this was you, "
                       "you can ignore this message.\n")),
        Scenario("dev/legit/zh-fund-statement", "dev", s, "Chinese financial statement",
                 "Fund company statement listing returns.",
                 build("招商银行 <statement@cmbchina.com>", "您的基金对账单（2026年9月）",
                       "尊敬的客户，您9月的基金对账单已生成，本月收益与持仓明细请登录手机银行查看。"
                       "基金有风险，投资需谨慎。\n")),
    ]


def _holdout_round_two() -> list[Scenario]:
    """Added 2026-10-09 after the round-two rule changes, before running them.

    Round-one holdout misses shaped the round-two dev categories, so that
    holdout no longer measures unseen messages on its own. This set is fresh:
    run once with its labels fixed, never used to tune rules."""
    s, p = "legitimate", "phishing"
    return [
        Scenario("holdout2/phish/remote-job-cheque", "holdout2", p, "job scam",
                 "Unsolicited remote job; a cheque is sent to buy equipment from the 'approved vendor'.",
                 build("Hiring Team <careers@brightpath-staffing.example>", "Offer: remote administrative assistant",
                       "Congratulations, after reviewing your profile you have been selected for a remote "
                       "administrative assistant role at $45 per hour. We will mail you a cheque to purchase "
                       "your work equipment from our approved vendor. Reply with your full name and address.\n")),
        Scenario("holdout2/phish/zh-brushing-task", "holdout2", p, "Chinese task scam",
                 "Part-time 'like and follow' task job that requires advancing money first.",
                 build("兼职招募 <hr@easy-task-jobs.example>", "在家兼职，日结佣金",
                       "只需手机点赞关注即可赚取佣金，每单10-50元，当天结算。新手任务需先垫付货款，"
                       "完成后连同佣金一起返还。添加客服QQ领取任务。\n")),
        Scenario("holdout2/phish/monash-password-expiry", "holdout2", p, "credential harvest",
                 "Password expiry notice linking to a domain that contains the university's name.",
                 build("Monash IT <it-notice@monash-sso-auth.example>", "Your password expires today",
                       "Your Monash password expires today. Keep your current password by confirming it below.\n",
                       html='<p>Your password expires today.</p>'
                            '<p><a href="https://monash-sso-auth.example/keep">Keep current password</a></p>')),
        Scenario("holdout2/phish/esign-settlement", "holdout2", p, "credential harvest",
                 "E-signature lure for a 'settlement agreement' linking to an unrelated host.",
                 build("Document Center <sign@docs-sign-portal.example>", "Please sign: Settlement agreement",
                       "You have received a document to review and sign: Settlement agreement.pdf.\n",
                       html='<p>Settlement agreement.pdf is waiting for your signature.</p>'
                            '<p><a href="https://docs-sign-portal.example/review?id=55">Review document</a></p>')),
        Scenario("holdout2/phish/scholarship-admin-fee", "holdout2", p, "advance fee",
                 "Unexpected scholarship that needs an administration fee to secure.",
                 build("Scholarships Office <awards@intl-scholarship-board.example>",
                       "You have been awarded an International Excellence Scholarship",
                       "We are pleased to inform you that you have been awarded AUD 10,000. To secure the "
                       "award, pay the AUD 150 administration fee by bank transfer within 48 hours.\n")),
        Scenario("holdout2/phish/zh-child-new-number", "holdout2", p, "Chinese family impersonation",
                 "Message claiming to be the reader's child with a new number needing money urgently.",
                 build("小明 <xiaoming.newphone@mail-host.example>", "妈，我换号了",
                       "妈，我手机坏了，这是我新邮箱。学校急着交一笔钱，你先帮我转3000到这个账户，"
                       "我晚点再跟你解释，先别给爸说。\n")),
        Scenario("holdout2/phish/svg-invoice", "holdout2", p, "HTML attachment",
                 "Invoice notice whose attachment is an SVG image.",
                 build("Billing <billing@cloud-invoices.example>", "Invoice INV-2290 overdue",
                       "Your invoice INV-2290 is overdue. Open the attached invoice for payment details.\n",
                       attachments=(("INV-2290.svg", "image", "svg+xml", b"<svg xmlns='http://www.w3.org/2000/svg'/>"),))),
        Scenario("holdout2/phish/lecturer-gift-card", "holdout2", p, "impersonation",
                 "Free-mail account using a lecturer's name asks for an urgent favour buying gift cards.",
                 build("Dr Sarah Chen <dr.sarahchen.office@gmail.com>", "Quick favour",
                       "Are you available? I'm in a meeting and need you to buy four Apple gift cards for "
                       "a student prize today. I'll reimburse you. Send me the codes when you have them.\n")),
        Scenario("holdout2/legit/auspost-tracking", "holdout2", s, "delivery notice",
                 "Real postal domain with tracking link on its own site.",
                 build("Australia Post <noreply@notifications.auspost.com.au>", "Your parcel is on its way",
                       "Your parcel is on its way and should arrive Tuesday.\n",
                       html='<p>Your parcel should arrive Tuesday.</p>'
                            '<p><a href="https://auspost.com.au/mypost/track/details/33ABC">Track parcel</a></p>')),
        Scenario("holdout2/legit/zh-jd-shipped", "holdout2", s, "Chinese order notice",
                 "Chinese retailer shipping notice from its own domain.",
                 build("京东 <order@jd.com>", "您的订单已发货",
                       "您好，您购买的商品已发货，预计2天内送达。可在京东App“我的订单”中查看物流。\n")),
        Scenario("holdout2/legit/scholarship-awarded", "holdout2", s, "university notice",
                 "Genuine scholarship award paid to the student's nominated account.",
                 build("Monash Scholarships <scholarships@monash.edu>", "Scholarship outcome",
                       "Congratulations, you have been awarded the Monash Merit Scholarship. Payments will be "
                       "made to the bank account in your student record. No action is needed.\n")),
        Scenario("holdout2/legit/esign-real", "holdout2", s, "e-signature",
                 "Real e-signature service domain with links on its own site.",
                 build("DocuSign <dse@docusign.net>", "Complete with DocuSign: Lease renewal",
                       "Your property manager sent you a document to review and sign.\n",
                       html='<p><a href="https://www.docusign.net/Signing/?ti=abc">Review document</a></p>')),
        Scenario("holdout2/legit/m365-renewal", "holdout2", s, "subscription notice",
                 "Real vendor subscription renewal notice.",
                 build("Microsoft <microsoft-noreply@microsoft.com>", "Your Microsoft 365 subscription will renew",
                       "Your Microsoft 365 Family subscription will renew on 1 November for $139.00. "
                       "To change this, visit https://account.microsoft.com/services\n")),
        Scenario("holdout2/legit/it-password-reminder", "holdout2", s, "IT notice",
                 "Genuine password expiry reminder pointing to the university's own site.",
                 build("Monash eSolutions <servicedesk@monash.edu>", "Your password will expire in 7 days",
                       "Your Monash password will expire in 7 days. Change it at https://my.monash.edu/password "
                       "or contact the service desk. We will never ask you to send your password.\n")),
    ]


def _dev_round_three() -> list[Scenario]:
    """Added 2026-10-09. Categories follow the holdout2 misses (job and task
    scams, family impersonation, e-signature lures, gift-card favours); the
    text is written fresh. Legitimate messages probe false alarms from rules
    for those categories."""
    s, p = "legitimate", "phishing"
    return [
        Scenario("dev/phish/reshipping-job", "dev", p, "job scam",
                 "Work-from-home 'parcel coordinator' job that turns the reader into a reshipping mule.",
                 build("Recruitment <jobs@globalparcel-logistics.example>", "Work from home: parcel coordinator",
                       "We found your resume online. Work from home as a parcel coordinator, no experience "
                       "needed, and earn $600 per week. Receive parcels at home and reship them to our "
                       "clients. Send a copy of your ID and your bank account number to get started.\n")),
        Scenario("dev/phish/zh-review-commission", "dev", p, "Chinese task scam",
                 "'Good review cashback' task that needs the reader to advance money.",
                 build("客服小李 <service@haoping-fanxian.example>", "好评返现，轻松赚佣金",
                       "您好，诚邀您参与商品好评任务，每单返现佣金5%-20%，在家即可操作。"
                       "前几单为小额体验，之后需先垫付本金，系统会连同佣金一起返还。\n")),
        Scenario("dev/phish/family-lost-phone", "dev", p, "family impersonation",
                 "Message claiming to be the reader's son from a new account asking for an urgent transfer.",
                 build("Jack <jack.temp.mail@mail-host.example>", "Hi Mum",
                       "Hi Mum, it's me. I lost my phone so I'm emailing from a new account. "
                       "I need to pay my rent today and my bank card is blocked. Can you transfer $1,800 "
                       "to my flatmate's account? I'll pay you back next week.\n")),
        Scenario("dev/phish/zh-relative-borrow", "dev", p, "Chinese family impersonation",
                 "Message claiming to be a nephew with a new contact asking to borrow money urgently.",
                 build("表弟阿杰 <ajie.new@mail-host.example>", "表哥，我是阿杰",
                       "表哥，我手机丢了，先用这个邮箱联系你。我这边出了点急事需要用钱，"
                       "能不能先帮我转两万到下面这个账户，过两天就还你。\n")),
        Scenario("dev/phish/docusign-lookalike", "dev", p, "credential harvest",
                 "E-signature notice using the DocuSign name from an unrelated domain.",
                 build("DocuSign via Signing Service <notify@esign-notify.example>",
                       "Completed: Please DocuSign Payroll_Update.pdf",
                       "A document is waiting for your signature: Payroll_Update.pdf.\n",
                       html='<p>Payroll_Update.pdf is waiting for your signature.</p>'
                            '<p><a href="https://esign-notify.example/doc/review">Review document</a></p>')),
        Scenario("dev/phish/manager-gift-card-favour", "dev", p, "impersonation",
                 "Free-mail account using a manager's name asks for gift card codes.",
                 build("Michael Turner <m.turner.manager@outlook.com>", "Are you free?",
                       "Hi, are you free at the moment? I need a quick favour. Please buy three Google Play "
                       "gift cards for a client and send me the codes as soon as possible. I'm in a "
                       "meeting so I can't take calls.\n")),
        Scenario("dev/legit/interview-invitation", "dev", s, "recruitment",
                 "Genuine interview invitation from an employer's own domain, after an application.",
                 build("Telstra Careers <careers@telstra.com>", "Interview invitation: Graduate Analyst",
                       "Thank you for applying for the Graduate Analyst role. You have been selected for "
                       "an interview. Please choose a time in the candidate portal.\n")),
        Scenario("dev/legit/casual-shifts", "dev", s, "workplace notice",
                 "Real university casual work notice with an hourly rate.",
                 build("Monash Casual Jobs <casual.jobs@monash.edu>", "Casual exam supervisor shifts available",
                       "Casual exam supervisor shifts are available in November at $38.50 per hour. "
                       "Apply through the staff portal by 20 October.\n")),
        Scenario("dev/legit/new-uni-email", "dev", s, "personal",
                 "Family member sharing a new email address without asking for anything.",
                 build("Jack Lee <jack.lee@student.monash.edu>", "My new email",
                       "Hi Mum, this is my new uni email. I lost my phone last week but got a new one, "
                       "so the number is the same. See you on Sunday!\n")),
        Scenario("dev/legit/docusign-real", "dev", s, "e-signature",
                 "Genuine DocuSign notice from DocuSign's own domain.",
                 build("Ray White via DocuSign <dse_na2@docusign.net>", "Please DocuSign: Lease agreement",
                       "Ray White sent you a document to review and sign.\n",
                       html='<p><a href="https://na2.docusign.net/Signing/EmailStart.aspx?a=1">Review document</a></p>')),
        Scenario("dev/legit/colleague-favour", "dev", s, "workplace request",
                 "Colleague asks a small favour that involves no money.",
                 build("Tom Nguyen <tom.nguyen@monash.edu>", "Quick favour",
                       "Hi, are you free this afternoon? Could you do me a quick favour and print the "
                       "tutorial handouts? They're in the shared drive. Thanks!\n")),
        Scenario("dev/legit/gift-card-receipt", "dev", s, "receipt",
                 "Genuine store receipt for a gift card purchase.",
                 build("Apple <no_reply@email.apple.com>", "Your receipt from Apple",
                       "Thank you for your purchase. App Store & iTunes Gift Card, $50.00. "
                       "The gift card code was sent to the recipient's email address.\n")),
    ]


def _holdout_round_three() -> list[Scenario]:
    """Added 2026-10-09 after the round-three rule changes, before running them.

    Round-three dev categories followed the holdout2 misses, so this fresh set
    is now the unseen measure. It deliberately mixes in categories no rule
    round has targeted. Run once with fixed labels; never used for tuning."""
    s, p = "legitimate", "phishing"
    return [
        Scenario("holdout3/phish/callback-antivirus", "holdout3", p, "callback phishing",
                 "Fake antivirus renewal with no links, only a phone number to 'cancel'.",
                 build("Norton Billing <billing@secure-renewals.example>", "Order confirmation #NT-88231",
                       "Your Norton 360 subscription has been renewed for $399.99 and will be charged to your "
                       "card on file. If you did not authorise this purchase, call our billing team on "
                       "+1 (888) 555-0142 within 24 hours to request a refund.\n")),
        Scenario("holdout3/phish/unpaid-toll", "holdout3", p, "payment lure",
                 "Unpaid toll notice with a late fee, linking to an unrelated payment host.",
                 build("Linkt <notice@toll-payments-au.example>", "Unpaid toll notice",
                       "You have an unpaid toll of $12.40. Pay now to avoid a $50 late fee.\n",
                       html='<p>You have an unpaid toll of $12.40.</p>'
                            '<p><a href="https://toll-payments-au.example/pay">Pay now</a></p>')),
        Scenario("holdout3/phish/zh-recall-compensation", "holdout3", p, "Chinese refund scam",
                 "Fake shop customer service offering triple compensation for a 'recalled' product.",
                 build("店铺客服 <kefu@shop-aftersale.example>", "关于您购买商品的召回赔偿",
                       "您好，您在本店购买的商品因质量问题被召回，我们将为您办理三倍赔偿。"
                       "请添加客服并提供银行卡信息，以便尽快为您退款。\n")),
        Scenario("holdout3/phish/zh-lottery-tax", "holdout3", p, "Chinese prize scam",
                 "Prize notice that requires paying 'tax' before collecting the winnings.",
                 build("幸运抽奖中心 <prize@lucky-draw-center.example>", "恭喜您中奖",
                       "恭喜您被抽中二等奖，奖金58,000元。按规定领奖前需先缴纳个人所得税2,000元，"
                       "请于三日内完成缴纳，逾期视为放弃。\n")),
        Scenario("holdout3/phish/wallet-airdrop", "holdout3", p, "crypto theft",
                 "Airdrop claim asking for the wallet recovery phrase.",
                 build("ETH Rewards <rewards@eth-airdrop-claim.example>", "Your airdrop is ready to claim",
                       "You are eligible for 0.85 ETH in our community airdrop. Connect your wallet and enter "
                       "your 12-word recovery phrase to claim it before the snapshot closes.\n")),
        Scenario("holdout3/phish/salary-adjustment", "holdout3", p, "credential harvest",
                 "'Salary adjustment letter' linking to a login page on an unrelated host.",
                 build("Human Resources <hr@staff-hr-notices.example>", "2027 salary adjustment letter",
                       "Your 2027 salary adjustment letter is now available. Sign in with your staff "
                       "account to view it.\n",
                       html='<p>Your salary adjustment letter is available.</p>'
                            '<p><a href="https://staff-hr-notices.example/sso/login">View letter</a></p>')),
        Scenario("holdout3/phish/disaster-donation", "holdout3", p, "charity scam",
                 "Disaster appeal asking for donations in bitcoin.",
                 build("Flood Relief Appeal <donate@flood-relief-fund.example>", "Help flood victims today",
                       "Thousands of families have lost their homes. Every dollar helps. Donations are "
                       "accepted in bitcoin to the wallet address below so funds arrive faster.\n")),
        Scenario("holdout3/phish/zh-visa-cancellation", "holdout3", p, "Chinese government impersonation",
                 "Fake immigration notice threatening visa cancellation unless a fine is paid.",
                 build("澳大利亚移民局 <visa-office@au-immigration-notice.example>", "签证取消通知",
                       "经核查，您的学生签证存在违规记录，将于48小时后被取消。如需申诉，请立即缴纳罚款"
                       "并提供护照首页照片。\n")),
        Scenario("holdout3/phish/onedrive-invoice", "holdout3", p, "credential harvest",
                 "Invoice shared 'via OneDrive' linking to a host that uses the OneDrive name.",
                 build("Accounts Receivable <ar@northside-supplies.example>", "Invoice 77120 shared with you",
                       "Please find invoice 77120 shared with you via OneDrive.\n",
                       html='<p><a href="https://onedrive-invoice-share.example/view/77120">View invoice</a></p>')),
        Scenario("holdout3/phish/mailbox-quota-mismatch", "holdout3", p, "credential harvest",
                 "Mailbox quota warning whose link text shows the university site but points elsewhere.",
                 build("Mail Administrator <admin@quota-alerts.example>", "Mailbox storage almost full",
                       "Your mailbox is 98% full. Increase your storage to keep receiving email.\n",
                       html='<p>Your mailbox is 98% full.</p>'
                            '<p><a href="https://quota-alerts.example/upgrade">https://my.monash.edu/mail</a></p>')),
        Scenario("holdout3/legit/toll-invoice", "holdout3", s, "bill",
                 "Real toll operator invoice linking to its own site.",
                 build("Linkt <noreply@linkt.com.au>", "Your Linkt statement is ready",
                       "Your monthly statement is ready. Your account will be debited automatically.\n",
                       html='<p><a href="https://www.linkt.com.au/account">View statement</a></p>')),
        Scenario("holdout3/legit/antivirus-renewal", "holdout3", s, "subscription notice",
                 "Real vendor renewal reminder from its own domain.",
                 build("Norton <noreply@norton.com>", "Your subscription renews soon",
                       "Your Norton 360 subscription will renew on 1 December. You can turn off automatic "
                       "renewal at any time in your Norton account.\n")),
        Scenario("holdout3/legit/donation-receipt", "holdout3", s, "receipt",
                 "Real charity donation receipt with a PDF.",
                 build("Australian Red Cross <supporter@redcross.org.au>", "Thank you for your donation",
                       "Thank you for your donation of $50 to the disaster relief appeal. Your tax receipt is "
                       "attached.\n",
                       attachments=(("receipt-2026-1009.pdf", "application", "pdf", FAKE),))),
        Scenario("holdout3/legit/payslip-available", "holdout3", s, "workplace notice",
                 "Real payslip notice pointing to the staff portal.",
                 build("Monash Payroll <payroll@monash.edu>", "Your payslip is available",
                       "Your payslip for the pay period ending 8 October is available in the staff portal.\n")),
        Scenario("holdout3/legit/zh-card-spending", "holdout3", s, "Chinese bank notice",
                 "Real bank spending alert.",
                 build("中国银行 <notice@boc.cn>", "账户支出提醒",
                       "您尾号1234的借记卡于10月9日支出人民币58.00元，余额请登录手机银行查询。"
                       "如非本人操作，请拨打卡背面客服电话。\n")),
        Scenario("holdout3/legit/visa-grant", "holdout3", s, "government notice",
                 "Real government visa grant notice.",
                 build("Department of Home Affairs <noreply@homeaffairs.gov.au>", "Visa grant notification",
                       "Your Student visa (subclass 500) has been granted. Your grant letter is available in "
                       "ImmiAccount.\n")),
        Scenario("holdout3/legit/friend-dinner", "holdout3", s, "personal",
                 "Friend asking about dinner from a free-mail account.",
                 build("Lily Zhang <lily.zhang.92@gmail.com>", "Dinner Friday?",
                       "Hey, are you free on Friday night? A few of us are going for hotpot in the city.\n")),
        Scenario("holdout3/legit/exchange-withdrawal", "holdout3", s, "financial notice",
                 "Real crypto exchange withdrawal confirmation.",
                 build("CoinSpot <noreply@coinspot.com.au>", "Withdrawal processed",
                       "Your withdrawal of 0.05 BTC has been processed. If you did not request this, "
                       "contact support immediately.\n")),
    ]


def _holdout_round_four() -> list[Scenario]:
    """Added 2026-10-09 after the round-four rule changes, before running them.

    ``variant-`` phishing scenarios reword categories earlier rounds covered,
    to test whether rules generalise within a category; ``new-`` scenarios are
    categories no round has targeted. Run once with fixed labels; never used
    for tuning."""
    s, p = "legitimate", "phishing"
    return [
        Scenario("holdout4/phish/variant-zh-police-video", "holdout4", p, "Chinese impersonation scam",
                 "Fake police say the reader's identity was used in fraud and demand a private video statement.",
                 build("刑侦支队 <case@sh-case-center.example>", "关于您身份信息被冒用的情况说明",
                       "您好，这里是市公安局刑侦支队。您的身份信息被他人用于开设银行账户，涉及一起诈骗案。"
                       "请配合调查，下载会议软件进行视频笔录，期间不得与他人联系。\n")),
        Scenario("holdout4/phish/variant-parcel-address", "holdout4", p, "delivery scam",
                 "Undeliverable parcel needing an address update and a small redirection charge.",
                 build("Parcel Delivery <support@parcel-redirect-au.example>", "We couldn't deliver your parcel",
                       "We tried to deliver your parcel but the address is incomplete. Update your address "
                       "and pay the $1.99 redirection charge to rebook delivery.\n",
                       html='<p><a href="https://parcel-redirect-au.example/update">Update address</a></p>')),
        Scenario("holdout4/phish/variant-m365-password", "holdout4", p, "credential harvest",
                 "Microsoft 365 password expiry from an unrelated domain.",
                 build("Microsoft 365 Admin <admin@tenant-security-mail.example>", "Password expiry notice",
                       "The password for your account expires today. Use the link below to keep your "
                       "current password.\n",
                       html='<p><a href="https://tenant-security-mail.example/keep">Keep password</a></p>')),
        Scenario("holdout4/phish/variant-ceo-wire", "holdout4", p, "business email compromise",
                 "Executive impersonation asking for an urgent, confidential payment to a new vendor.",
                 build("Daniel Moore <daniel.moore.ceo@outlook.com>", "Confidential",
                       "I need you to process a payment of $24,500 to a new vendor today. I'll send the "
                       "account details shortly. Keep this between us until the deal is announced.\n")),
        Scenario("holdout4/phish/variant-zh-rental-deposit", "holdout4", p, "Chinese rental scam",
                 "Landlord who is 'away on business' wants a deposit before any viewing.",
                 build("陈先生 <chen.fangdong@mail-host.example>", "房子还在，可以租",
                       "你好，房子还在。我在外地出差，钥匙放在朋友那里。你先把一个月定金打到我卡上，"
                       "我让朋友直接带你入住。\n")),
        Scenario("holdout4/phish/variant-gold-trading", "holdout4", p, "investment scam",
                 "'Wrong number' contact that steers toward a gold trading platform.",
                 build("Amy Lin <amy.lin.trader@mail-host.example>", "Sorry, wrong email?",
                       "Hi, sorry if I have the wrong address. By the way, I trade gold futures on my "
                       "uncle's platform and made 40% last month. I can show you how to start with $1,000.\n")),
        Scenario("holdout4/phish/new-sextortion", "holdout4", p, "extortion",
                 "Claims to have recorded the reader and demands bitcoin.",
                 build("Unknown <x9k2@mail-host.example>", "I know what you did",
                       "I recorded you through your webcam. Pay $1,500 in Bitcoin within 48 hours or I "
                       "will send the video to all your contacts.\n")),
        Scenario("holdout4/phish/new-domain-expiry", "holdout4", p, "renewal scam",
                 "Fake domain expiry notice linking to an unrelated renewal site.",
                 build("Domain Services <renew@domain-renew-center.example>", "Domain expiry: kaiq7an.dev",
                       "Your domain kaiq7an.dev expires today. Renew now to avoid losing your website "
                       "and email.\n",
                       html='<p><a href="https://domain-renew-center.example/renew">Renew domain</a></p>')),
        Scenario("holdout4/phish/new-zh-loan-unfreeze", "holdout4", p, "Chinese loan scam",
                 "Loan offer that needs an 'unfreeze fee' before release.",
                 build("快捷贷款 <loan@fast-cash-cn.example>", "您的贷款已审批通过",
                       "您申请的无抵押低息贷款50,000元已审批通过，因银行卡号填写有误资金被冻结，"
                       "需先交500元解冻费即可当天放款。\n")),
        Scenario("holdout4/phish/new-fake-recruiter-app", "holdout4", p, "job scam",
                 "Recruiter moves the conversation to a chat app for an 'interview'.",
                 build("Talent Acquisition <hr@remote-hiring-partners.example>", "Interview for Data Entry Clerk",
                       "Your application has been shortlisted. Interviews are held on Telegram. Install the "
                       "app and message our HR manager to schedule your interview today.\n")),
        Scenario("holdout4/legit/amazon-delivered", "holdout4", s, "delivery notice",
                 "Real retailer delivery confirmation.",
                 build("Amazon.com.au <shipment-tracking@amazon.com.au>", "Delivered: your package",
                       "Your package was delivered and left at the front door.\n")),
        Scenario("holdout4/legit/github-token", "holdout4", s, "security notice",
                 "Real developer platform security notice.",
                 build("GitHub <noreply@github.com>", "A personal access token was added to your account",
                       "A fine-grained personal access token was recently added to your account. If this "
                       "wasn't you, review your account security settings.\n")),
        Scenario("holdout4/legit/rent-reminder", "holdout4", s, "property notice",
                 "Real agency rent reminder.",
                 build("Ray White Clayton <rentals.clayton@raywhite.com>", "Rent reminder",
                       "This is a friendly reminder that your rent of $480 is due on 15 October. Please pay "
                       "using your usual method.\n")),
        Scenario("holdout4/legit/tuition-fee-due", "holdout4", s, "university notice",
                 "Real tuition reminder that mentions late fees.",
                 build("Monash Student Fees <fees@monash.edu>", "Tuition fees due 31 October",
                       "Your Semester 2 tuition fees are due by 31 October. Unpaid fees may incur a late "
                       "fee and a hold on your enrolment.\n")),
        Scenario("holdout4/legit/zh-didi-invoice", "holdout4", s, "Chinese receipt",
                 "Real ride-hailing trip invoice.",
                 build("滴滴出行 <invoice@didiglobal.com>", "您的行程电子发票",
                       "您好，您申请的行程电子发票已开具，金额36.50元，请查收附件。\n",
                       attachments=(("didi-invoice.pdf", "application", "pdf", FAKE),))),
        Scenario("holdout4/legit/telco-outage", "holdout4", s, "service notice",
                 "Real telco planned outage notice.",
                 build("Telstra <noreply@telstra.com>", "Planned maintenance in your area",
                       "We're upgrading the network in your area on 14 October between 1am and 5am. "
                       "Your service may be briefly unavailable.\n")),
        Scenario("holdout4/legit/friend-lunch-money", "holdout4", s, "personal",
                 "Friend asking to borrow a small amount face to face.",
                 build("Ben Wu <ben.wu.mel@gmail.com>", "lunch",
                       "Hey, forgot my wallet. Can you spot me $15 for lunch when I see you at 12? "
                       "I'll pay you back tonight.\n")),
        Scenario("holdout4/legit/zh-wechat-bill", "holdout4", s, "Chinese bill",
                 "Real payment platform monthly bill.",
                 build("微信支付 <wxpay@tencent.com>", "您的9月账单已生成",
                       "您9月共支出2,315.60元，收入500.00元，详细账单可在微信支付中查看。\n")),
    ]


def _holdout_round_five() -> list[Scenario]:
    """Added 2026-10-09 after the round-five intent rules, before running them.
    ``variant-`` rewords covered categories; ``new-`` categories were never
    targeted. Run once with fixed labels; never used for tuning."""
    s, p = "legitimate", "phishing"
    return [
        Scenario("holdout5/phish/variant-zh-customs-parcel", "holdout5", p, "Chinese delivery scam",
                 "International parcel 'held by customs' until duties are paid on a linked page.",
                 build("国际物流中心 <service@intl-express-cn.example>", "您的国际包裹已被扣留",
                       "您好，您的国际包裹因申报信息不完整被暂扣。请在48小时内通过下方页面补全收件信息"
                       "并支付关税，超时包裹将被退回。\nhttps://intl-express-cn.example/clear\n")),
        Scenario("holdout5/phish/variant-bank-card-hold", "holdout5", p, "bank impersonation",
                 "Bank card 'temporarily held' with a link to a host using the bank's name.",
                 build("CommBank Alerts <alerts@commbank-card-services.example>", "Temporary hold on your card",
                       "We've placed a temporary hold on your card after unusual activity. Review recent "
                       "transactions to restore access.\n",
                       html='<p><a href="https://commbank-card-services.example/review">Review activity</a></p>')),
        Scenario("holdout5/phish/variant-zh-stock-teacher", "holdout5", p, "Chinese investment scam",
                 "Stock 'teacher' who recommends daily picks in a private group.",
                 build("李老师助理 <assistant.li@stock-picks-club.example>", "免费领取今日牛股",
                       "李老师每天在群里免费推荐牛股，上周学员平均盈利35%。扫码进群即可领取，"
                       "名额只剩最后10个。\n")),
        Scenario("holdout5/phish/variant-grandchild-bail", "holdout5", p, "family impersonation",
                 "'Grandson' in trouble asks for bail money and secrecy.",
                 build("Ethan <ethan.help.now@mail-host.example>", "Grandma please help",
                       "Grandma, it's Ethan. I had a car accident and I'm at the police station. I need "
                       "$3,000 for bail today. Please don't tell Mum, she'll be so upset.\n")),
        Scenario("holdout5/phish/variant-mystery-shopper", "holdout5", p, "job scam",
                 "Mystery shopper job that has the reader move money through a transfer service.",
                 build("Shopper Program <assign@retail-evaluators.example>", "Your first mystery shopping assignment",
                       "Welcome to our mystery shopper program. We will deposit $2,000 into your account. "
                       "Keep $300 as your pay and send the rest through a money transfer service to "
                       "evaluate it.\n")),
        Scenario("holdout5/phish/variant-mygov-message", "holdout5", p, "government impersonation",
                 "Fake myGov inbox notice linking to a host using the myGov name.",
                 build("myGov <inbox@mygov-messages-au.example>", "You have a new message",
                       "You have a new message about your tax refund. Sign in to view it.\n",
                       html='<p><a href="https://mygov-messages-au.example/signin">Sign in</a></p>')),
        Scenario("holdout5/phish/variant-pastor-gift-cards", "holdout5", p, "impersonation",
                 "Free-mail 'pastor' asks for gift cards and photos of their backs.",
                 build("Pastor John Reid <pastor.john.reid@gmail.com>", "Request",
                       "Hello, I need you to get some gift cards for cancer patients I'm visiting today. "
                       "Scratch the back and send me pictures of them. I'll refund you on Sunday.\n")),
        Scenario("holdout5/phish/new-overpayment-refund", "holdout5", p, "refund scam",
                 "Claims an accidental over-refund and asks for the difference back.",
                 build("Refund Department <refunds@account-refund-desk.example>", "Refund error on your account",
                       "Due to a system error we refunded $4,900 instead of $49 to your account. Please "
                       "return the difference of $4,851 today to avoid legal action.\n")),
        Scenario("holdout5/phish/new-zh-campus-loan", "holdout5", p, "Chinese credit scam",
                 "Fake finance platform says a student loan account must be closed to protect credit.",
                 build("金融服务中心 <service@credit-help-cn.example>", "关于注销校园贷账户的通知",
                       "根据最新规定，您在校期间开通的校园贷账户需要注销，否则将影响个人征信。"
                       "请联系客服，按指引将账户余额转入监管账户完成注销。\n")),
        Scenario("holdout5/phish/new-booking-reconfirm", "holdout5", p, "booking scam",
                 "Hotel booking needs card details 'reconfirmed' or it will be cancelled.",
                 build("Booking Partner Desk <reservations@hotel-reconfirm.example>", "Action needed for your booking",
                       "Your reservation at Harbour View Hotel could not be guaranteed. Reconfirm your card "
                       "details within 12 hours or your booking will be cancelled.\n",
                       html='<p><a href="https://hotel-reconfirm.example/guarantee">Reconfirm booking</a></p>')),
        Scenario("holdout5/phish/new-legal-callback", "holdout5", p, "callback phishing",
                 "Threat of legal action with a phone number to call, but no link.",
                 build("Legal Department <legal@debt-recovery-notice.example>", "Final notice before legal action",
                       "A claim has been filed against you for an outstanding debt. To stop legal "
                       "proceedings, call our legal department on +61 2 5550 1234 today.\n")),
        Scenario("holdout5/phish/new-cloud-billing-suspension", "holdout5", p, "credential harvest",
                 "Cloud account 'suspended for billing' with a link to an unrelated console host.",
                 build("Cloud Billing <billing@cloud-console-billing.example>", "Account suspended: billing problem",
                       "Your cloud account has been suspended because of a billing problem. Update your "
                       "payment method to restore your services.\n",
                       html='<p><a href="https://cloud-console-billing.example/billing">Update billing</a></p>')),
        Scenario("holdout5/legit/commbank-statement", "holdout5", s, "bank notice",
                 "Real bank statement notice.",
                 build("CommBank <statements@commbank.com.au>", "Your statement is ready",
                       "Your statement for the period ending 30 September is ready to view in NetBank.\n")),
        Scenario("holdout5/legit/mygov-inbox", "holdout5", s, "government notice",
                 "Real government inbox notice.",
                 build("myGov <noreply@my.gov.au>", "You have a new message in myGov",
                       "You have a new message in your myGov inbox. Sign in to myGov to read it.\n")),
        Scenario("holdout5/legit/store-refund", "holdout5", s, "receipt",
                 "Real store refund confirmation.",
                 build("JB Hi-Fi <orders@jbhifi.com.au>", "Your refund has been processed",
                       "We've refunded $49.00 to your original payment method. It may take 3-5 business "
                       "days to appear.\n")),
        Scenario("holdout5/legit/booking-confirmed", "holdout5", s, "booking",
                 "Real booking confirmation.",
                 build("Booking.com <noreply@booking.com>", "Your booking is confirmed",
                       "Your stay at Harbour View Hotel from 12 to 14 December is confirmed. You'll pay at "
                       "the property.\n")),
        Scenario("holdout5/legit/cloud-bill", "holdout5", s, "bill",
                 "Real cloud provider monthly bill.",
                 build("Amazon Web Services <no-reply@aws.amazon.com>", "Your AWS bill is available",
                       "Your AWS bill for September is $3.42. It will be charged to your card on file.\n")),
        Scenario("holdout5/legit/grandchild-visit", "holdout5", s, "personal",
                 "Grandchild arranging a visit.",
                 build("Ethan Brown <ethan.brown.04@gmail.com>", "Visiting Saturday",
                       "Hi Grandma, I'm coming on the train Saturday. Could you pick me up from the station "
                       "at 11? Can't wait to see you!\n")),
        Scenario("holdout5/legit/library-overdue", "holdout5", s, "university notice",
                 "Real library overdue notice with a replacement charge.",
                 build("Monash Library <library@monash.edu>", "Final notice: overdue item",
                       "The item 'Introduction to Algorithms' is overdue. Return or renew it by Friday to "
                       "avoid a replacement charge of $120.\n")),
        Scenario("holdout5/legit/it-remote-support", "holdout5", s, "IT notice",
                 "Real IT ticket update about a requested remote session.",
                 build("Monash eSolutions <servicedesk@monash.edu>", "Ticket 4411: remote session booked",
                       "As requested, a technician will connect to your laptop with remote access at 2pm "
                       "today to fix the printer driver.\n")),
        Scenario("holdout5/legit/zh-sf-delivered", "holdout5", s, "Chinese delivery notice",
                 "Real courier delivery confirmation.",
                 build("顺丰速运 <notice@sf-express.com>", "您的快递已签收",
                       "您好，您的快递已于今日10:15签收，感谢使用顺丰速运。\n")),
        Scenario("holdout5/legit/zh-securities-notice", "holdout5", s, "Chinese financial notice",
                 "Real brokerage reminder about risk.",
                 build("华泰证券 <service@htsc.com.cn>", "投资者风险提示",
                       "尊敬的客户，近期市场波动较大，请理性投资。任何承诺高收益的“荐股群”均为诈骗，"
                       "请勿添加陌生人微信。\n")),
    ]


def _holdout_round_six() -> list[Scenario]:
    """Added 2026-10-09 after the round-six rules, before running them. More
    legitimate messages than earlier holdouts, because the larger rule set
    raises the risk of false alarms. Run once; never used for tuning."""
    s, p = "legitimate", "phishing"
    return [
        Scenario("holdout6/phish/variant-parcel-storage-fee", "holdout6", p, "delivery scam",
                 "Postal brand on an unrelated domain asking for a storage fee.",
                 build("AusPost <noreply@auspost-delivery-hub.example>", "Your item is waiting",
                       "Your item is waiting at our facility. Confirm your delivery preferences and settle "
                       "the $0.80 storage fee to avoid return to sender.\n",
                       html='<p><a href="https://auspost-delivery-hub.example/prefs">Confirm preferences</a></p>')),
        Scenario("holdout6/phish/variant-zh-romance-platform", "holdout6", p, "Chinese investment scam",
                 "Friendly stranger steers toward an 'insider' trading platform.",
                 build("Sophie <sophie.chen.life@mail-host.example>", "认识你很开心",
                       "最近聊得很开心～我舅舅是做数字资产分析的，有内部消息，我跟着在一个平台做了三个月，"
                       "每次都稳定盈利。你想试试的话我教你注册。\n")),
        Scenario("holdout6/phish/variant-dad-vet-bill", "holdout6", p, "family impersonation",
                 "'Child' on a borrowed account needs money for a vet bill.",
                 build("Mia <mia.borrowed.acc@mail-host.example>", "Dad it's Mia",
                       "Dad, my phone died and I'm on a friend's email. Biscuit is at the emergency vet and "
                       "they need $700 before they'll treat him. Can you send it to the account below?\n")),
        Scenario("holdout6/phish/variant-tiktok-ban", "holdout6", p, "account threat",
                 "Unprotected platform brand threatening a ban unless ownership is verified.",
                 build("TikTok Safety <review@tiktok-safety-review.example>", "Final warning: account ban",
                       "Your account violates our community guidelines and will be permanently banned in "
                       "24 hours. Verify your ownership to file an objection.\n",
                       html='<p><a href="https://tiktok-safety-review.example/verify">Verify ownership</a></p>')),
        Scenario("holdout6/phish/variant-zh-subsidy", "holdout6", p, "Chinese government impersonation",
                 "Fake labour bureau subsidy asking for bank card details.",
                 build("人社局补贴办 <butie@rsj-subsidy.example>", "失业补贴领取通知",
                       "您符合本年度失业补贴发放条件，补贴金额3,600元。请登录下方网页填写姓名、身份证号"
                       "和银行卡号完成领取。\nhttps://rsj-subsidy.example/apply\n")),
        Scenario("holdout6/phish/variant-supplier-new-banking", "holdout6", p, "business email compromise",
                 "Supplier says its banking has changed, from a lookalike domain.",
                 build("Accounts <accounts@officeworks-billing.example>", "Change to our banking",
                       "Please note our banking has changed effective immediately. Use the account in the "
                       "attached letter for this and all future invoices.\n",
                       attachments=(("new-banking-letter.pdf", "application", "pdf", FAKE),))),
        Scenario("holdout6/phish/new-payid-upgrade", "holdout6", p, "marketplace scam",
                 "Buyer claims a payment is held until the seller pays to 'upgrade' to a business account.",
                 build("PayID Support <support@payid-business-verify.example>", "Payment pending: action required",
                       "A buyer has sent you $350 via PayID. The funds are pending because your account is "
                       "not a business account. Ask the buyer to cover the upgrade or pay $100 yourself; "
                       "it will be returned with the payment.\n")),
        Scenario("holdout6/phish/new-airbnb-off-platform", "holdout6", p, "rental scam",
                 "Host asks to book directly outside the platform by bank transfer.",
                 build("Host Daniel <daniel.stays@mail-host.example>", "Book direct and save",
                       "Thanks for your interest in the apartment. If we book directly instead of through "
                       "the app, I can take 15% off. Just pay the full amount by bank transfer.\n")),
        Scenario("holdout6/phish/new-code-forwarding", "holdout6", p, "account takeover",
                 "Asks the reader to pass on a login code 'sent by mistake'.",
                 build("Chris <chris.k.temp@mail-host.example>", "Sent my code to you by mistake",
                       "Hey, I accidentally put your number when logging in and the 6-digit code went to "
                       "your phone. Could you forward it to me? Thanks heaps.\n")),
        Scenario("holdout6/phish/new-enrolment-fee", "holdout6", p, "university impersonation",
                 "Enrolment cancellation threat over an unpaid fee, linking to a payment host.",
                 build("Student Finance <finance@student-fee-portal.example>", "Enrolment cancellation notice",
                       "Your enrolment will be cancelled on Friday because your student services fee is "
                       "outstanding. Pay online now to keep your place.\n",
                       html='<p><a href="https://student-fee-portal.example/pay">Pay fee</a></p>')),
        Scenario("holdout6/phish/new-zh-service-close", "holdout6", p, "Chinese customer-service scam",
                 "Fake payment app support says a paid insurance feature must be closed via a link.",
                 build("支付平台客服 <kefu@pay-guarantee-cn.example>", "百万保障即将扣费",
                       "您开通的百万保障服务试用期已满，将于明日起每月自动扣费688元。如非本人开通，"
                       "请点击链接关闭服务。\nhttps://pay-guarantee-cn.example/close\n")),
        Scenario("holdout6/phish/new-crypto-recovery", "holdout6", p, "recovery scam",
                 "Promises to recover lost crypto for an upfront fee.",
                 build("Asset Recovery <cases@crypto-recovery-experts.example>", "We can recover your funds",
                       "Lost money to an online trading scam? Our certified team recovers stolen crypto. "
                       "An upfront retainer of $1,200 is required to open your case.\n")),
        Scenario("holdout6/legit/auspost-collect", "holdout6", s, "delivery notice",
                 "Real postal collection notice.",
                 build("Australia Post <noreply@notifications.auspost.com.au>", "Your parcel is ready to collect",
                       "Your parcel is ready to collect from Clayton Post Office. Bring your ID. It will be "
                       "held for 10 business days.\n")),
        Scenario("holdout6/legit/student-asks-parent", "holdout6", s, "personal",
                 "Student asking a parent for textbook money from their usual address.",
                 build("Mia Brown <mia.brown@student.monash.edu>", "textbook",
                       "Hi Dad, could you send me $50 for the stats textbook? I'll pay you back when I get "
                       "paid on Friday. Love, Mia\n")),
        Scenario("holdout6/legit/tiktok-removal", "holdout6", s, "platform notice",
                 "Real platform content removal notice.",
                 build("TikTok <noreply@account.tiktok.com>", "Your video was removed",
                       "Your video was removed for violating community guidelines. You can appeal this "
                       "decision in the app.\n")),
        Scenario("holdout6/legit/zh-gov-subsidy", "holdout6", s, "Chinese government notice",
                 "Real government subsidy notice from a government domain.",
                 build("人力资源和社会保障局 <service@rsj.sh.gov.cn>", "补贴发放通知",
                       "您申请的职业技能补贴已审核通过，将发放至您登记的社保卡账户，无需其他操作。\n")),
        Scenario("holdout6/legit/supplier-banking-unchanged", "holdout6", s, "workplace notice",
                 "Real supplier warning that its banking has not changed.",
                 build("Officeworks Accounts <accounts@officeworks.com.au>", "Our bank details have not changed",
                       "We are aware of scam emails claiming our bank details have changed. Our bank details "
                       "have not changed; please call your account manager if in doubt.\n")),
        Scenario("holdout6/legit/ticket-receipt", "holdout6", s, "receipt",
                 "Real ticketing receipt.",
                 build("Ticketek <noreply@ticketek.com.au>", "Your tickets",
                       "Thanks for your order. Your two tickets for 14 March are attached as mobile tickets.\n")),
        Scenario("holdout6/legit/airbnb-confirmed", "holdout6", s, "booking",
                 "Real rental platform confirmation reminding guests to pay on-platform.",
                 build("Airbnb <automated@airbnb.com>", "Reservation confirmed",
                       "Your reservation is confirmed. Always communicate and pay through Airbnb to stay "
                       "protected.\n")),
        Scenario("holdout6/legit/login-code", "holdout6", s, "security notice",
                 "Real login code email.",
                 build("GitHub <noreply@github.com>", "Your GitHub launch code",
                       "Here is your GitHub launch code: 48213907. If you didn't try to sign in, change your "
                       "password.\n")),
        Scenario("holdout6/legit/ssaf-due", "holdout6", s, "university notice",
                 "Real student services fee reminder.",
                 build("Monash Student Fees <fees@monash.edu>", "SSAF due 31 October",
                       "Your Student Services and Amenities Fee is due by 31 October. Pay through WES or "
                       "defer it to SA-HELP.\n")),
        Scenario("holdout6/legit/zh-alipay-bill", "holdout6", s, "Chinese bill",
                 "Real payment app monthly bill.",
                 build("支付宝 <service@mail.alipay.com>", "您的10月账单已出",
                       "您10月账单已出，本期应还1,286.40元，还款日为11月9日。\n")),
        Scenario("holdout6/legit/exchange-security-tip", "holdout6", s, "security notice",
                 "Real exchange reminding users it never asks for a seed phrase.",
                 build("CoinSpot <noreply@coinspot.com.au>", "Security reminder",
                       "Scammers are impersonating exchanges. CoinSpot will never ask for your seed phrase, "
                       "password or 2FA codes.\n")),
        Scenario("holdout6/legit/vcat-hearing", "holdout6", s, "government notice",
                 "Real tribunal hearing notice.",
                 build("VCAT <noreply@vcat.vic.gov.au>", "Notice of hearing",
                       "A hearing for your rental bond application is listed for 20 November at 10am. "
                       "Details are in the attached notice.\n",
                       attachments=(("notice-of-hearing.pdf", "application", "pdf", FAKE),))),
        Scenario("holdout6/legit/seek-job-alert", "holdout6", s, "job alert",
                 "Real job board alert listing remote roles.",
                 build("SEEK <jobmail@s.seek.com.au>", "12 new jobs for 'data analyst'",
                       "12 new jobs match your saved search, including work from home roles in Melbourne.\n")),
        Scenario("holdout6/legit/zh-hotpot-split", "holdout6", s, "personal",
                 "Friend splitting a dinner bill.",
                 build("王磊 <wanglei.mel@gmail.com>", "火锅AA",
                       "今晚火锅一共348，四个人，每人87，微信转我就行。\n")),
    ]


def _holdout_round_seven() -> list[Scenario]:
    """Added 2026-10-09 after the negation change, before running it. Mostly
    ordinary inbox mail, especially marketing and app notices that use
    pressure, prizes, QR codes and chat apps for legitimate reasons, to
    measure false alarms of the larger rule set. Run once; never used for
    tuning."""
    s, p = "legitimate", "phishing"
    return [
        Scenario("holdout7/legit/flash-sale", "holdout7", s, "marketing",
                 "Retail flash sale with countdown pressure.",
                 build("THE ICONIC <hello@email.theiconic.com.au>", "Ends tonight: 40% off",
                       "Last chance! Our biggest sale ends tonight at midnight. Act now to save 40% on "
                       "thousands of styles.\n")),
        Scenario("holdout7/legit/loyalty-draw-winner", "holdout7", s, "marketing",
                 "Supermarket loyalty program prize with a claim deadline.",
                 build("Flybuys <noreply@flybuys.com.au>", "You've won 5,000 bonus points",
                       "Congratulations, you've won 5,000 bonus points in our weekly draw! Claim your prize "
                       "in the app within 7 days.\n")),
        Scenario("holdout7/legit/cafe-qr-menu", "holdout7", s, "marketing",
                 "Cafe newsletter about ordering by QR code.",
                 build("Brother Baba Budan <news@brotherbababudan.com.au>", "New: order at your table",
                       "You can now scan the QR code on your table to order and pay without queuing.\n")),
        Scenario("holdout7/legit/gym-whatsapp", "holdout7", s, "community",
                 "Gym inviting members to a WhatsApp group for class updates.",
                 build("Monash Sport <sport@monash.edu>", "Join the class updates group",
                       "We've started a WhatsApp group for class changes and cancellations. Add our number "
                       "from the front desk to join.\n")),
        Scenario("holdout7/legit/energy-bill-overdue", "holdout7", s, "bill",
                 "Real energy retailer overdue reminder.",
                 build("AGL <noreply@agl.com.au>", "Your bill is overdue",
                       "Your electricity bill of $214.60 is now overdue. Please pay within 7 days to avoid a "
                       "late payment fee. Pay in the AGL app or at agl.com.au.\n")),
        Scenario("holdout7/legit/uber-eats-promo", "holdout7", s, "marketing",
                 "Food delivery promotion.",
                 build("Uber Eats <uber@uber.com>", "Free delivery this weekend",
                       "Enjoy free delivery on orders over $25 this weekend. Offer ends Sunday.\n")),
        Scenario("holdout7/legit/zh-taobao-coupon", "holdout7", s, "Chinese marketing",
                 "Shopping app coupon with a deadline.",
                 build("淘宝 <noreply@service.taobao.com>", "您有一张满减券即将过期",
                       "您的满300减40优惠券将于今日24点过期，立即使用享受优惠。\n")),
        Scenario("holdout7/legit/zh-meituan-delivery", "holdout7", s, "Chinese delivery notice",
                 "Food delivery app arrival notice.",
                 build("美团外卖 <noreply@meituan.com>", "骑手已送达",
                       "您的外卖已送达，如有问题可在App内联系客服。祝您用餐愉快！\n")),
        Scenario("holdout7/legit/linkedin-recruiter", "holdout7", s, "recruitment",
                 "Recruiter message via LinkedIn about a real role.",
                 build("LinkedIn <messages-noreply@linkedin.com>", "Sarah sent you a message",
                       "Sarah Lee: Hi Kai, I'm hiring for a graduate security analyst role at Deloitte. "
                       "Would you be open to a quick call next week?\n")),
        Scenario("holdout7/legit/bank-new-payee", "holdout7", s, "bank notice",
                 "Bank confirming a new payee the customer added.",
                 build("ING <noreply@ing.com.au>", "New payee added",
                       "You added a new payee, J Smith, on 9 October. If this wasn't you, call us on "
                       "133 464 straight away.\n")),
        Scenario("holdout7/legit/airline-checkin", "holdout7", s, "travel",
                 "Airline check-in reminder.",
                 build("Qantas <noreply@qantas.com.au>", "Check in now for your flight",
                       "Check-in is now open for your flight QF401 to Sydney tomorrow. Check in online and "
                       "download your boarding pass.\n")),
        Scenario("holdout7/legit/zoom-recording", "holdout7", s, "workplace notice",
                 "Meeting recording available.",
                 build("Zoom <no-reply@zoom.us>", "Cloud recording is now available",
                       "The cloud recording of 'FIT3178 consultation' is now available. Share it with your "
                       "team from the Zoom web portal.\n")),
        Scenario("holdout7/legit/strava-challenge", "holdout7", s, "app notice",
                 "Fitness app challenge with a reward.",
                 build("Strava <no-reply@strava.com>", "You completed the October 5K challenge",
                       "Nice work! You completed the October 5K Challenge. Claim your reward badge in the app.\n")),
        Scenario("holdout7/legit/zh-wechat-security", "holdout7", s, "Chinese security notice",
                 "Real messaging app login notice.",
                 build("微信团队 <weixin@tencent.com>", "微信登录提醒",
                       "你的微信帐号于10月9日在新设备登录。如非本人操作，请立即在手机上修改密码。\n")),
        Scenario("holdout7/legit/landlord-maintenance", "holdout7", s, "property notice",
                 "Agency arranging maintenance access.",
                 build("Barry Plant Clayton <pm.clayton@barryplant.com.au>", "Plumber visit Thursday",
                       "A plumber will attend on Thursday between 9am and 12pm to fix the hot water. Keys "
                       "will be collected from our office; you don't need to be home.\n")),
        Scenario("holdout7/legit/charity-monthly-donor", "holdout7", s, "charity",
                 "Charity thanking a monthly donor.",
                 build("Oxfam Australia <supporter@oxfam.org.au>", "Your monthly gift at work",
                       "Thank you for your monthly donation. This year, supporters like you helped 12,000 "
                       "families access clean water.\n")),
        Scenario("holdout7/legit/tax-agent-reminder", "holdout7", s, "professional services",
                 "Tax agent reminding a client to send documents.",
                 build("H&R Block <noreply@hrblock.com.au>", "Lodge before 31 October",
                       "Your tax return is due by 31 October. Upload your income statement so we can lodge "
                       "it for you.\n")),
        Scenario("holdout7/legit/student-union-election", "holdout7", s, "university notice",
                 "Student union election reminder.",
                 build("MSA <elections@monashstudentassociation.com>", "Voting closes tomorrow",
                       "Voting in the MSA elections closes tomorrow at 5pm. Log in with your student account "
                       "to vote.\n")),
        Scenario("holdout7/legit/zh-alipay-transfer-receipt", "holdout7", s, "Chinese receipt",
                 "Payment app transfer receipt.",
                 build("支付宝 <service@mail.alipay.com>", "转账成功",
                       "您已成功向王磊转账87.00元。\n")),
        Scenario("holdout7/legit/parcel-locker", "holdout7", s, "delivery notice",
                 "Parcel locker collection code.",
                 build("Australia Post <noreply@notifications.auspost.com.au>", "Your parcel is in a locker",
                       "Your parcel is in Parcel Locker 3168 Clayton. Use collection code 482913 within 2 days.\n")),
        Scenario("holdout7/legit/github-sponsor-payout", "holdout7", s, "platform notice",
                 "Platform payout notice.",
                 build("GitHub Sponsors <noreply@github.com>", "Your payout is on its way",
                       "Your GitHub Sponsors payout of $35.00 has been sent to your bank account ending 4421.\n")),
        Scenario("holdout7/legit/lecturer-extension", "holdout7", s, "university notice",
                 "Lecturer approving an assignment extension.",
                 build("Dr Sarah Chen <sarah.chen@monash.edu>", "Re: extension request",
                       "Hi Kai, your extension is approved. Please submit by Friday 5pm and keep this email "
                       "as confirmation.\n")),
        Scenario("holdout7/legit/zh-bank-promo", "holdout7", s, "Chinese marketing",
                 "Bank card promotion.",
                 build("招商银行 <promotion@cmbchina.com>", "刷卡赢好礼",
                       "本月使用招行信用卡消费满3笔，即可参与抽奖，有机会赢取iPad。活动详情请见掌上生活App。\n")),
        Scenario("holdout7/legit/airbnb-host-message", "holdout7", s, "booking",
                 "Host message relayed by the platform.",
                 build("Airbnb <express@airbnb.com>", "Message from your host",
                       "Daniel: Hi! Check-in is from 3pm. The lockbox code will be sent through the app on "
                       "the day. Enjoy your stay.\n")),
        Scenario("holdout7/phish/variant-zh-parcel-claim", "holdout7", p, "Chinese delivery scam",
                 "Lost parcel compensation that needs card details.",
                 build("快递理赔中心 <lipei@express-claims-cn.example>", "包裹丢失赔付",
                       "您的快递在运输中丢失，我们将按三倍赔付。请回复您的姓名、银行卡号和收到的验证码，"
                       "以便赔款到账。\n")),
        Scenario("holdout7/phish/variant-boss-urgent-transfer", "holdout7", p, "business email compromise",
                 "Free-mail 'CFO' wants an urgent transfer kept quiet.",
                 build("Rachel Kim <rachel.kim.cfo@gmail.com>", "Urgent transfer",
                       "Can you transfer $9,800 to the vendor account below before noon? I'm boarding a "
                       "flight. Please don't mention this to anyone until it's done.\n")),
        Scenario("holdout7/phish/new-fake-unsubscribe", "holdout7", p, "credential harvest",
                 "Spam complaint notice whose 'unsubscribe' link asks for a mailbox login.",
                 build("Mail Compliance <compliance@mailbox-optout.example>", "Too many spam complaints",
                       "Your mailbox has received too many spam reports. Sign in to confirm your email "
                       "preferences or sending will be restricted.\n",
                       html='<p><a href="https://mailbox-optout.example/signin">Confirm preferences</a></p>')),
        Scenario("holdout7/phish/new-zh-education-refund", "holdout7", p, "Chinese refund scam",
                 "Fake training school refund that requires a 'deposit' to release.",
                 build("培训退费处 <tuifei@edu-refund-cn.example>", "课程退费通知",
                       "您之前报名的网课可申请全额退费。系统需先验证您的还款能力，请先存入1,000元保证金，"
                       "退费将连同保证金一起返还。\n")),
        Scenario("holdout7/phish/new-pet-deposit", "holdout7", p, "pet scam",
                 "Puppy seller who cannot meet and wants a transport deposit.",
                 build("Puppy Haven <breeder.lucy@mail-host.example>", "Your puppy is ready",
                       "Max is ready for his new home! As I'm interstate, I'll arrange pet transport. "
                       "Please pay the $450 transport deposit by PayID today to secure him.\n")),
        Scenario("holdout7/phish/new-fake-invoice-dispute", "holdout7", p, "malware delivery",
                 "Invoice dispute with a disk image attachment.",
                 build("Billing Dispute <disputes@invoice-check-team.example>", "Disputed charge INV-7781",
                       "A charge on your account has been disputed. Review the attached statement and reply "
                       "within 48 hours.\n",
                       attachments=(("statement-7781.iso", "application", "octet-stream", FAKE),))),
    ]


SCENARIOS: tuple[Scenario, ...] = tuple(_dev_legitimate() + _dev_phishing() + _dev_round_two() + _dev_round_three() + _dev_round_four() + _dev_round_five() + _dev_round_six() + _dev_round_seven() + _dev_round_eight() + _holdout() + _holdout_round_two() + _holdout_round_three() + _holdout_round_four() + _holdout_round_five() + _holdout_round_six() + _holdout_round_seven())


# Scenario id -> why the current rules miss it. Remove an entry when it is fixed.
KNOWN_GAPS: dict[str, str] = {
    "dev/legit/newsletter-tracked-url-text":
        "Click tracking whose visible text is the final URL reads as an anchor mismatch; only Constant "
        "Contact's documented route is calibrated, deliberately not a general mailing-service allowlist.",
    "dev/phish/bonus-letter-login": "A 'log in to view' request with a link to the sender's own login page reads like "
                                    "a genuine HR portal notice; telling them apart needs sender reputation.",
    "dev/legit/whatsapp-own-notice": "The chat app's own notice is read as moving the conversation to a chat app.",
    "dev/phish/zh-ask-password-a": "Asking for a password by reply scores only one medium signal; data-loss "
                                   "threats (数据丢失) are not recognised.",
    "holdout2/phish/remote-job-cheque": "Missed by the round-two rules (holdout2: not used for tuning).",
    "holdout2/phish/esign-settlement": "Missed by the round-two rules (holdout2: not used for tuning).",
    "holdout3/phish/unpaid-toll": "Missed by the round-three rules (holdout3: not used for tuning).",
    "holdout3/phish/salary-adjustment": "Missed by the round-three rules (holdout3: not used for tuning).",
    "holdout3/phish/disaster-donation": "Missed by the round-three rules (holdout3: not used for tuning).",
    "holdout3/phish/onedrive-invoice": "Missed by the round-three rules (holdout3: not used for tuning).",
    "holdout4/phish/variant-ceo-wire": "Missed by the round-four rules (holdout4: not used for tuning).",
    "holdout4/phish/variant-gold-trading": "Missed by the round-four rules (holdout4: not used for tuning).",
    "holdout5/phish/variant-zh-customs-parcel": "Missed by the round-five rules (holdout5: not used for tuning).",
    "holdout6/phish/variant-zh-romance-platform": "Missed by the round-six rules (holdout6: not used for tuning).",
    "holdout6/phish/variant-dad-vet-bill": "Missed by the round-six rules (holdout6: not used for tuning).",
    "holdout6/phish/variant-tiktok-ban": "Missed by the round-six rules (holdout6: not used for tuning).",
    "holdout6/phish/variant-zh-subsidy": "Missed by the round-six rules (holdout6: not used for tuning).",
    "holdout6/phish/variant-supplier-new-banking": "Missed by the round-six rules (holdout6: not used for tuning).",
    "holdout6/phish/new-payid-upgrade": "Missed by the round-six rules (holdout6: not used for tuning).",
    "holdout6/phish/new-airbnb-off-platform": "Missed by the round-six rules (holdout6: not used for tuning).",
    "holdout6/phish/new-code-forwarding": "Missed by the round-six rules (holdout6: not used for tuning).",
    "holdout6/phish/new-enrolment-fee": "Missed by the round-six rules (holdout6: not used for tuning).",
    "holdout6/phish/new-zh-service-close": "Missed by the round-six rules (holdout6: not used for tuning).",
    "holdout6/phish/new-crypto-recovery": "Missed by the round-six rules (holdout6: not used for tuning).",
    "holdout7/phish/new-fake-unsubscribe": "Missed by the rules after the negation change (holdout7: not used for tuning).",
    "holdout7/phish/new-zh-education-refund": "Missed by the rules after the negation change (holdout7: not used for tuning).",
    "holdout7/phish/new-pet-deposit": "Missed by the rules after the negation change (holdout7: not used for tuning).",
    "holdout7/legit/loyalty-draw-winner": "False alarm: a loyalty prize with a claim deadline reads as a windfall "
                                          "lure with time pressure.",
    "holdout7/legit/zh-wechat-security": "False alarm: the chat app's own login notice mentions WeChat and "
                                         "advises changing the password (修改密码).",
}
