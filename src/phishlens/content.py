"""Social-engineering signals in the subject and body, in English and Chinese.

Each signal fires at most once and reports the phrases that matched, so the
reader can see exactly why it fired.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Signal:
    code: str
    severity: str
    title: str
    phrases: tuple[str, ...]
    patterns: tuple[str, ...] = ()  # regular expressions, for phrases with numbers


SIGNALS: tuple[Signal, ...] = (
    Signal("content.urgency", "low", "Creates time pressure", (
        "urgent", "immediately", "within 24 hours", "within 48 hours", "final notice", "act now",
        "account will be suspended", "account has been suspended", "expires today", "expire today",
        "final reminder", "今天到期", "今日到期",
        "立即", "立刻", "马上", "紧急", "24小时内", "24 小时内", "逾期", "冻结", "最后通知",
    ), (r"\bwithin \d{1,2} (?:hours|days)\b", r"\d{1,2}\s*(?:小时|天|日)内", r"[一二两三四五六七]\s*(?:天|日)内")),
    Signal("content.credentials", "medium", "Asks for a password, code or identity details", (
        "verify your account", "confirm your password", "reset your password", "enter your password",
        "update your payment", "login to verify", "verification code", "one-time code",
        "bank account number", "copy of your id", "copy of your passport",
        "card details", "verify your card", "update your card", "card number",
        "密码", "验证码", "登录验证", "账户验证", "身份证号", "银行卡号", "身份证照片", "银行卡信息", "信用卡信息",
    )),
    Signal("content.payment", "medium", "Asks for money or an unusual payment method", (
        "gift card", "wire transfer", "bank transfer", "bitcoin", "western union", "processing fee",
        "redelivery fee", "customs fee", "clearance fee", "bank details", "new account details",
        "usdt", "crypto wallet", "can you transfer", "could you transfer", "please transfer",
        "转账", "汇款", "保证金", "手续费", "安全账户", "比特币", "清关费", "西联", "收款账户", "银行账户变更",
        "垫付", "帮我转", "转给我", "借钱", "需要用钱", "急需用钱",
        "late fee", "penalty", "unpaid", "postage fee", "缴纳", "罚款", "滞纳金", "邮费",
        "must be paid", "needs to be paid", "押金", "定金", "订金", "打过来", "监管账户",
        "礼品卡", "购物卡", "充值卡", "京东卡", "e卡",
    ), (
        # A payment verb or "payment of" followed closely by an amount.
        r"\b(?:pay|send|transfer|wire|remit)\s+(?:[\w-]+\s+){0,4}?[$€£¥]\s?\d",
        r"\bpayment of\s+[$€£¥]\s?\d",
        # Money sent to "my"/"this" card or account.
        r"(?:到|给|进)(?:我|我的|这个|指定)(?:的)?(?:卡|账户|账号|银行卡)",
        r"\bto (?:my|our|this|the following)\s+(?:[\w'-]+\s+){0,2}account\b",
        r"\b(?:import|customs)\s+(?:duty|duties|tax|fees?)\s+(?:of\s+)?[$€£¥]\s?\d",
    )),
    Signal("content.overpayment", "medium", "Says you were paid or refunded too much and asks for it back", (
        "overpaid", "overpayment", "refunded twice", "issued twice", "duplicate refund", "send back the",
        "refund the extra", "return the difference", "refund the difference",
        "多付", "多转", "转错", "退还差额", "多退",
    )),
    Signal("content.money_mule", "high", "Asks you to receive money and pass it on, which makes you a money mule", (
        "forward the remainder", "forward the rest", "send the rest", "send the remainder",
        "transfer the rest", "pass on the rest", "receive customer payments", "receive payments into your account",
        "代收款", "代收", "剩余的钱", "剩下的钱",
    ), (r"\bkeep\s+(?:\d{1,2}%|[$€£¥]\s?\d)", r"留下\s*\d{1,2}%")),
    Signal("content.legal_threat", "medium", "Threatens legal action or debt collection", (
        "legal action", "legal proceedings", "court proceedings", "court summons", "debt collector",
        "lawsuit", "起诉", "法院传票", "律师函", "法律责任", "诉讼",
    )),
    Signal("content.wallet_secret", "high", "Asks for a wallet recovery phrase or private key, which no genuine service requests", (
        "seed phrase", "recovery phrase", "secret phrase", "private key", "助记词", "私钥",
    )),
    Signal("content.windfall", "medium", "Announces a prize, reward or unexpected payout", (
        "you have won", "you've won", "claim your prize", "claim your reward", "airdrop",
        "中奖", "抽中", "领奖", "幸运大奖", "免费领取",
    )),
    Signal("content.job_offer", "medium", "Offers unsolicited work, commission or easy income", (
        "work from home", "no experience needed", "no experience required", "found your resume",
        "found your cv", "reship", "shortlisted", "hiring manager",
        "在家兼职", "在家即可", "兼职", "佣金", "返现", "刷单", "日结", "简历", "入职",
    )),
    Signal("content.off_channel", "medium", "Moves the conversation to a chat app or private contact", (
        "whatsapp", "telegram", "wechat", "kakaotalk", "viber", "add her number", "add his number",
        "add my number", "message me on", "text me on",
        "微信", "加客服", "添加客服", "私聊", "加好友",
    )),
    Signal("content.remote_access", "medium", "Asks you to share your screen or allow remote access", (
        "remote access", "anydesk", "teamviewer", "share your screen", "screen sharing", "screen share",
        "屏幕共享", "共享屏幕", "远程控制", "远程协助", "会议软件",
    )),
    Signal("content.cold_open", "low", "Opens as if the message reached the wrong person", (
        "wrong number", "wrong person", "wrong contact", "sorry to bother you", "is this still your",
        "加错人", "发错人",
    )),
    Signal("content.delivery", "low", "Concerns a parcel or delivery", (
        "parcel", "package", "courier", "depot", "shipment", "delivery",
        "包裹", "快递", "派送", "物流",
    )),
    Signal("content.new_contact", "medium", "Says they have a new phone, number or account", (
        "lost my phone", "my phone broke", "my phone is broken", "my new number", "this is my new number",
        "from a new account", "from a new email",
        "手机丢了", "手机坏了", "换号了", "新号码", "新微信", "这个邮箱联系",
    )),
    Signal("content.favour", "medium", "Opens with a vague favour or says they cannot take calls", (
        "quick favour", "quick favor", "are you free", "are you available", "i'm in a meeting",
        "can't take calls", "cannot take calls", "send me the codes", "send the codes",
        "帮个忙", "在开会", "不方便接电话",
    )),
    Signal("content.investment", "medium", "Promises guaranteed or unusually high investment returns", (
        "guaranteed return", "guaranteed profit", "guaranteed income", "double your money",
        "forex", "futures", "外汇", "期货",
        "稳赚", "保本保息", "高额回报", "带单", "日收益",
    ), (
        r"\b\d{1,3}%\s*(?:a|per|each|every)\s+(?:day|week|month)\b",
        r"\b(?:made|earn(?:ed|ing)?|returns?|profits?)\b\D{0,15}\d{1,3}%",
        r"\d{1,3}%\s*(?:profit|return)",
        r"(?:收益|回报|盈利)\D{0,6}\d{1,3}%",
    )),
    Signal("content.remote_deal", "medium", "Wants money from someone you cannot meet or inspect", (
        "currently overseas", "unable to show you", "send you the keys", "mail you the keys",
        "before inspection", "before the inspection", "away on business", "out of town",
        "out of the country",
        "在海外", "人在国外", "人不在国内", "不在国内", "在外地", "回不去", "无法看房", "无法带你看房",
        "钥匙寄给你", "钥匙快递", "钥匙交给你", "先付押金", "先交押金",
    )),
    Signal("content.account_threat", "medium", "Threatens to disable or delete an account or page", (
        "copyright infringement", "will be disabled", "will be permanently deleted", "scheduled for deletion",
        "violated our community", "violates our community", "submit an appeal",
        "will be deleted", "avoid losing", "has lapsed", "will lapse", "will be cancelled",
        "will be canceled", "将被取消", "征信", "不良记录",
        "侵犯版权", "版权侵权", "将被封禁", "永久封禁", "将被删除", "违反社区",
    )),
    Signal("content.qr_code", "medium", "Asks you to scan a QR code, which hides the link from checks", (
        "scan the qr code", "scan this qr code", "scan the code with your phone",
        "扫描二维码", "扫码",
    )),
    Signal("content.authority", "medium", "Claims to be police, a court or a government office", (
        "police", "embassy", "consulate", "arrest warrant", "money laundering", "under investigation", "interpol",
        "taxation office", "tax office", "internal revenue service", "hmrc",
        "公安", "警察", "警官", "大使馆", "领事馆", "海关", "涉嫌", "洗钱", "通缉", "立案", "办案", "税务局", "税务总局",
    )),
    Signal("content.secrecy", "high", "Tells you to keep it secret or cut off contact", (
        "do not tell", "don't tell", "keep this confidential", "do not contact your family",
        "do not call the police", "don't call the police", "between you and me", "don't discuss",
        "do not discuss", "don't mention this", "do not mention this",
        "保密", "不要告诉", "切勿告知", "不得透露", "断联", "不要联系家人", "不要报警", "别报警",
        "不要和任何人说", "不要跟任何人说", "不要声张", "没有人的房间",
    )),
)


# A phone number introduced by "call"/"致电" and at least eight digits long,
# so dates, amounts and short service numbers are not mistaken for one.
_CALL_NUMBER_RE = re.compile(r"(?:\bcall\b|\bphone\b|\bdial\b|致电|拨打)\D{0,25}?(\+?\d[\d\s().-]{6,}\d)")
_CHARGE_PHRASES = ("charged", "renewed", "renewal", "to cancel", "refund", "legal", "court", "debt",
                   "续费", "扣款", "取消", "退款", "起诉", "欠款", "诉讼")


def find_signals(text: str) -> list[tuple[Signal, list[str]]]:
    lowered = text.lower()
    hits: list[tuple[Signal, list[str]]] = []
    for signal in SIGNALS:
        matched = [phrase for phrase in signal.phrases if phrase.lower() in lowered]
        for pattern in signal.patterns:
            matched += [m.group(0) for m in re.finditer(pattern, lowered)]
        matched = list(dict.fromkeys(matched))  # a phrase and a pattern can find the same words
        if matched:
            hits.append((signal, matched))
    return hits


def find_callback_number(text: str) -> str | None:
    """Return a phone number offered to dispute a charge or legal claim, the
    shape of callback phishing, which moves the scam to a call no link check sees."""
    lowered = text.lower()
    if not any(phrase in lowered for phrase in _CHARGE_PHRASES):
        return None
    for match in _CALL_NUMBER_RE.finditer(lowered):
        number = match.group(1)
        if sum(ch.isdigit() for ch in number) >= 8:
            return number.strip()
    return None
