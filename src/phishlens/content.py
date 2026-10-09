"""Social-engineering signals in the subject and body, in English and Chinese.

Each signal fires at most once and reports the phrases that matched, so the
reader can see exactly why it fired.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Signal:
    code: str
    severity: str
    title: str
    phrases: tuple[str, ...]


SIGNALS: tuple[Signal, ...] = (
    Signal("content.urgency", "low", "Creates time pressure", (
        "urgent", "immediately", "within 24 hours", "within 48 hours", "final notice", "act now",
        "account will be suspended", "account has been suspended", "expires today",
        "立即", "立刻", "马上", "紧急", "24小时内", "24 小时内", "逾期", "冻结", "最后通知",
    )),
    Signal("content.credentials", "medium", "Asks for a password, code or identity details", (
        "verify your account", "confirm your password", "reset your password", "enter your password",
        "update your payment", "login to verify", "verification code", "one-time code",
        "bank account number", "copy of your id", "copy of your passport",
        "密码", "验证码", "登录验证", "账户验证", "身份证号", "银行卡号", "身份证照片",
    )),
    Signal("content.payment", "medium", "Asks for money or an unusual payment method", (
        "gift card", "wire transfer", "bank transfer", "bitcoin", "western union", "processing fee",
        "redelivery fee", "customs fee", "clearance fee", "bank details", "new account details",
        "usdt", "crypto wallet", "can you transfer", "could you transfer", "please transfer",
        "转账", "汇款", "保证金", "手续费", "安全账户", "比特币", "清关费", "西联", "收款账户", "银行账户变更",
        "垫付", "帮我转", "转给我", "借钱", "需要用钱", "急需用钱",
    )),
    Signal("content.job_offer", "medium", "Offers unsolicited work, commission or easy income", (
        "work from home", "no experience needed", "no experience required", "found your resume",
        "found your cv", "reship",
        "在家兼职", "在家即可", "兼职", "佣金", "返现", "刷单", "日结",
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
        "稳赚", "保本保息", "高额回报", "带单", "日收益",
    )),
    Signal("content.remote_deal", "medium", "Wants money from someone you cannot meet or inspect", (
        "currently overseas", "unable to show you", "send you the keys", "mail you the keys",
        "before inspection", "before the inspection",
        "在海外", "人在国外", "无法看房", "无法带你看房", "钥匙寄给你", "先付押金", "先交押金",
    )),
    Signal("content.account_threat", "medium", "Threatens to disable or delete an account or page", (
        "copyright infringement", "will be disabled", "will be permanently deleted", "scheduled for deletion",
        "violated our community", "violates our community", "submit an appeal",
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
        "do not call the police", "don't call the police",
        "保密", "不要告诉", "切勿告知", "不得透露", "断联", "不要联系家人", "不要报警", "别报警",
    )),
)


def find_signals(text: str) -> list[tuple[Signal, list[str]]]:
    lowered = text.lower()
    hits: list[tuple[Signal, list[str]]] = []
    for signal in SIGNALS:
        matched = [phrase for phrase in signal.phrases if phrase.lower() in lowered]
        if matched:
            hits.append((signal, matched))
    return hits
