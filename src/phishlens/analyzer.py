"""Turn a parsed email into a scored, explained report."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from . import attachments as attachment_rules
from .auth import AuthVerdicts, parse_authentication_results
from .content import CHAT_APP_DOMAINS, GIFT_CARD_PAYMENT_RE, asking_text, find_callback_number, find_signals
from .domains import (FREE_MAIL_DOMAINS, brand_terms, custom_brands, find_lookalike, is_government, is_ip,
                      is_mixed_script, protected_brands, protected_domains, registrable_domain, same_site,
                      to_unicode)
from .intel import OfflineIntel, ThreatIntel
from .mailings import mailing_service, tracking_service
from .message import DEFAULT_MAX_BYTES, Attachment, ParsedEmail, parse_file
from .model import Model
from .scoring import Finding, risk_level, sort_findings, total_score
from .urls import URL_SHORTENERS, Link, extract_text_links, parse_html, strip_urls

_EMAIL_IN_TEXT_RE = re.compile(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)")
_DNS_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", re.ASCII)

_LOOKALIKE_TITLES = {
    "homoglyph": "uses lookalike characters to imitate",
    "brand-in-subdomain": "hides a real domain inside a different one, imitating",
    "tld-swap": "uses the right name with the wrong ending, imitating",
    "typosquat": "is one letter away from",
    "brand-keyword": "borrows the brand name of",
}


@dataclass
class Report:
    source: str
    email: ParsedEmail
    auth: AuthVerdicts | None
    findings: list[Finding]
    links: list[Link] = field(default_factory=list)

    @property
    def score(self) -> int:
        return total_score(self.findings)

    @property
    def level(self) -> str:
        return risk_level(self.score)

    @property
    def attachments(self) -> list[Attachment]:
        return self.email.attachments


def _auth_findings(auth: AuthVerdicts | None) -> list[Finding]:
    if auth is None:
        return [Finding("auth.missing", "low",
                        "No Authentication-Results header: the sender could not be verified")]
    findings = []
    if auth.dmarc in ("fail", "reject", "quarantine"):
        findings.append(Finding("auth.dmarc_fail", "high",
                                "DMARC failed in the recorded results: sender-domain alignment was not accepted",
                                f"dmarc={auth.dmarc}"))
    if auth.spf == "fail":
        findings.append(Finding("auth.spf_fail", "medium",
                                "SPF failed in the recorded results: the sending server was not authorised",
                                f"spf={auth.spf}"))
    elif auth.spf == "softfail":
        findings.append(Finding("auth.spf_softfail", "low",
                                "SPF soft-failed: the sending server is probably not authorised",
                                f"spf={auth.spf}"))
    if auth.dkim == "fail":
        findings.append(Finding("auth.dkim_fail", "medium",
                                "DKIM failed in the recorded results: the reporting server could not validate the signature",
                                f"dkim={auth.dkim}"))
    elif auth.dkim in (None, "none"):
        findings.append(Finding("auth.dkim_missing", "low", "No usable DKIM pass/fail result was recorded",
                                f"dkim={auth.dkim or 'missing'}"))
    return findings


def _mailing_context(email: ParsedEmail, auth: AuthVerdicts | None) -> str | None:
    """Recorded passes permit routing context, never a sender-safety verdict."""
    if (email.sender is None or auth is None or auth.warnings or email.parsing_warnings
            or (auth.spf, auth.dkim, auth.dmarc) != ("pass", "pass", "pass")):
        return None
    return mailing_service(email.sender.domain)


def _ordinary_reply_domain(domain: str) -> bool:
    labels = domain.split(".")
    return (len(domain) <= 253 and len(labels) >= 2
            and all(_DNS_LABEL_RE.fullmatch(label) for label in labels)
            and not is_ip(domain) and not is_mixed_script(domain)
            and find_lookalike(domain) is None)


def _ordinary_visible_site(link: Link) -> bool:
    """Only plain visible site names/URLs qualify for the narrow calibration.

    Encoded text remains outside this pattern rather than trying to infer how a
    browser or a redirect would decode it. No destination is fetched or trusted.
    """
    visible = link.anchor_text
    if (not visible.isascii() or any(ch.isspace() or ord(ch) < 33 or ord(ch) == 127
                                     for ch in visible)
            or "%" in visible or "\\" in visible):
        return False
    url = visible if visible.lower().startswith(("http://", "https://")) else "https://" + visible
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        port = 443 if parts.scheme == "https" else 80
        return (parts.scheme in ("http", "https") and _ordinary_reply_domain(host)
                and not any(label.startswith("xn--") for label in host.split("."))
                and host == link.anchor_host() and parts.username is None
                and parts.password is None and parts.port in (None, port)
                and (":" not in parts.netloc or parts.netloc.endswith(f":{port}")))
    except ValueError:
        return False


def _header_findings(email: ParsedEmail, provider: str | None = None, trusted_sender: str = "") -> list[Finding]:
    sender = email.sender
    if sender is None or not sender.domain:
        return [Finding("header.no_sender", "medium", "The From address is missing or malformed")]
    findings = []
    lookalike = find_lookalike(sender.domain)
    if lookalike:
        findings.append(Finding("header.from_lookalike", "high" if lookalike.technique != "brand-keyword" else "medium",
                                f"The sender's domain {_LOOKALIKE_TITLES[lookalike.technique]} {lookalike.imitates}",
                                to_unicode(sender.domain)))

    name = sender.display_name.lower()
    for brand, domains in protected_brands().items():
        term = next((t for t in brand_terms(brand) if re.search(rf"\b{re.escape(t)}\b", name)), None)
        if term and not any(same_site(sender.domain, d) for d in domains):
            findings.append(Finding("header.display_name_brand", "high",
                                    f"The display name says '{term.title()}' but the address is not one of {brand.title()}'s domains",
                                    str(sender)))
            break
    for match in _EMAIL_IN_TEXT_RE.finditer(sender.display_name):
        if not same_site(match.group(1), sender.domain):
            findings.append(Finding("header.display_name_address", "high",
                                    "The display name shows a different email address from the real sender",
                                    str(sender)))
            break

    replies = [reply for reply in email.reply_to
               if reply.domain and not same_site(reply.domain, sender.domain)]
    malformed = [reply for reply in email.reply_to if not reply.domain]
    if malformed:
        findings.append(Finding("header.reply_to_malformed", "medium",
                                "A Reply-To address is missing a usable domain",
                                ", ".join(reply.address or "(empty address)" for reply in malformed[:3])))
    if replies:
        ordinary = not malformed and all(_ordinary_reply_domain(r.domain) for r in replies)
        context = provider and ordinary
        # An authenticated organisation often routes replies to a help desk or
        # mailing service. Free-mail reply targets stay medium: they are the
        # usual sign of a compromised or spoofed business account.
        helpdesk = (not context and trusted_sender and ordinary
                    and not any(registrable_domain(r.domain) in FREE_MAIL_DOMAINS for r in replies))
        if context:
            title = f"Replies use a different domain from a {provider} sender address; this can occur with From rewriting"
        elif helpdesk:
            title = ("Replies go to a different domain from the authenticated sender "
                     "(common with help desks and mailing services)")
        else:
            title = "Replies go to a different domain from the sender"
        findings.append(Finding("header.reply_to_mismatch", "low" if context or helpdesk else "medium", title,
                                f"From {sender.domain}, Reply-To {', '.join(r.address for r in replies[:3])}"))
        # Inspect all reply targets, so an ordinary first address cannot hide a
        # later brand lookalike. A routing pattern does not waive these findings.
        seen_reply_domains: set[str] = set()
        for reply in replies:
            lookalike = find_lookalike(reply.domain)
            if lookalike and reply.domain not in seen_reply_domains:
                seen_reply_domains.add(reply.domain)
                findings.append(Finding("header.reply_to_lookalike",
                                        "medium" if lookalike.technique == "brand-keyword" else "high",
                                        f"The Reply-To domain {_LOOKALIKE_TITLES[lookalike.technique]} {lookalike.imitates}",
                                        to_unicode(reply.domain)))
    if email.return_path and "@" in email.return_path:
        bounce_domain = email.return_path.rpartition("@")[2]
        if not same_site(bounce_domain, sender.domain):
            findings.append(Finding("header.return_path_mismatch", "info",
                                    "Bounces go to a different domain (common for mailing services)",
                                    f"Return-Path {email.return_path}"))
    return findings


def _link_findings(links: list[Link], provider: str | None = None,
                   sender_domain: str = "", trusted_sender: str = "") -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()

    def add(code: str, severity: str, title: str, evidence: str, key: str) -> None:
        if (code, key) not in seen:
            seen.add((code, key))
            findings.append(Finding(code, severity, title, evidence))

    for link in links:
        host = link.host
        if link.source == "form":
            add("url.form", "medium", "The email contains a form that submits data to a website", link.url, host)
        if not host:
            continue
        claimed = link.anchor_mismatch()
        if claimed:
            route_context = (provider and link.source == "html"
                             and _ordinary_visible_site(link)
                             and not link.anchor_looks_like_login
                             and not any(same_site(claimed, domain) for domain in protected_domains())
                             and find_lookalike(claimed) is None and not is_mixed_script(claimed)
                             and tracking_service(link.url, sender_domain) == provider)
            if route_context:
                # Separate codes prevent a low routing warning from deduping
                # away a later high mismatch to the same intermediary host.
                add("url.tracking_destination_unverified", "low",
                    f"Link text shows {claimed} via a {provider} tracking route; final destination is unverified",
                    link.url, host)
            elif (trusted_sender and _ordinary_visible_site(link) and same_site(claimed, trusted_sender)
                  and not is_ip(host) and find_lookalike(host) is None and not is_mixed_script(host)):
                # The sender passed SPF, DKIM and DMARC for its own domain, and the
                # text names that same site: click tracking, not a disguise. The
                # reverse (other text over a link to the sender's own site) is
                # deliberately not reduced; that is how a phisher's own domain
                # hides behind a trusted name.
                add("url.own_site_destination_unverified", "low",
                    f"Link text shows the authenticated sender's site {claimed} but the link goes through "
                    f"{to_unicode(host)}; final destination is unverified", link.url, host)
            else:
                add("url.anchor_mismatch", "high",
                    f"Link text shows {claimed} but the link goes to {to_unicode(host)}", link.url, host)
        if link.has_userinfo:
            add("url.userinfo", "high", "The link hides its real destination after an '@'", link.url, host)
        if is_ip(host):
            add("url.ip_host", "medium", "The link points to a bare IP address instead of a domain", link.url, host)
            continue
        lookalike = find_lookalike(host)
        if lookalike:
            severity = "medium" if lookalike.technique == "brand-keyword" else "high"
            code = "url.brand_keyword" if lookalike.technique == "brand-keyword" else "url.lookalike"
            add(code, severity, f"Link domain {_LOOKALIKE_TITLES[lookalike.technique]} {lookalike.imitates}",
                f"{to_unicode(host)} ({link.url})", host)
        elif host.startswith("xn--") or ".xn--" in host:
            add("url.punycode", "medium", "Link domain uses encoded international characters",
                f"{to_unicode(host)} ({host})", host)
        if is_mixed_script(host) and not lookalike:
            add("url.mixed_script", "medium", "Link domain mixes alphabets", to_unicode(host), host)
        if host in URL_SHORTENERS:
            add("url.shortener", "low", "The link uses a URL shortener that hides its destination", link.url, host)
        if link.scheme == "http" and link.looks_like_login:
            add("url.insecure_login", "low", "A login-style link is not encrypted (http)", link.url, host)
    return findings


_AUTHORITY_ASKS = {"content.payment", "content.credentials", "content.secrecy", "content.wallet_secret"}
_GIFT_CARD_RE = re.compile(r"gift cards?|itunes cards?|google play cards?|steam cards?|礼品卡|购物卡|充值卡|京东卡|e卡")
_GIFT_CARD_CODES_RE = re.compile(r"\b(?:card numbers|card codes|the codes|codes? on the back|scratch|"
                                 r"(?:photos|pictures) of|the back of)\b|卡密|刮开|拍照")


def _content_findings(email: ParsedEmail, visible_html_text: str) -> list[Finding]:
    # The sender's display name is read as part of the message: impersonation
    # often lives there ("公安局", "Embassy") rather than in the body.
    display_name = email.sender.display_name if email.sender else ""
    text = strip_urls("\n".join((display_name, email.subject, email.text, visible_html_text)))
    findings = []
    hits = find_signals(text)
    codes = {signal.code for signal, _ in hits}
    identity = "\n".join((display_name, email.subject)).lower()
    sender_domain = email.sender.domain if email.sender else ""
    for signal, matched in hits:
        if signal.code == "content.off_channel" and sender_domain:
            matched = [m for m in matched
                       if not any(same_site(sender_domain, d) for d in CHAT_APP_DOMAINS.get(m, ()))]
            if not matched:
                continue
        evidence = ", ".join(f"'{m}'" for m in matched[:5])
        if signal.code == "content.authority" and email.sender and not is_government(email.sender.domain):
            # Mentioning the police in passing is ordinary ("contact Victoria
            # Police"). Claiming to be an authority in the sender name or
            # subject, or pairing the claim with a request, is the scam shape.
            if any(m.lower() in identity for m in matched) or codes & _AUTHORITY_ASKS:
                findings.append(Finding("content.authority_non_gov", "high",
                                        "Claims to be police, a tax office or government but was not sent from a government domain",
                                        f"{evidence}; sender {email.sender.domain}"))
                continue
        if signal.code == "content.delivery" and not codes & {"content.payment", "content.credentials"}:
            # Parcel wording is everyday mail ("free delivery"); it only adds
            # risk as the setting for a request for money or card details,
            # the parcel-fee shape.
            findings.append(Finding(signal.code, "info", "Concerns a parcel or delivery (scored only with a "
                                    "request for money or details)", evidence))
            continue
        findings.append(Finding(signal.code, signal.severity, signal.title, evidence))
    asking = asking_text(text)
    if ((_GIFT_CARD_RE.search(asking) and _GIFT_CARD_CODES_RE.search(asking))
            or re.search(GIFT_CARD_PAYMENT_RE, asking)):
        findings.append(Finding("content.gift_card_codes", "high",
                                "Asks for payment in gift cards or for their codes, which work like cash once shared",
                                "gift card payment or codes requested"))
    if number := find_callback_number(text):
        findings.append(Finding("content.callback", "high",
                                "Reports a charge or legal claim and gives a phone number to dispute it, a common way to move a scam to a call",
                                number))
    return findings


def _attachment_findings(email: ParsedEmail, visible_html_text: str = "") -> list[Finding]:
    findings = []
    text = "\n".join((email.subject, email.text, visible_html_text))
    for attachment in email.attachments:
        issues = attachment_rules.classify(attachment)
        if encrypted := attachment_rules.encrypted_archive(attachment, text):
            issues.append(encrypted)
        for severity, code, explanation in issues:
            findings.append(Finding(code, severity, explanation, f"sha256 {attachment.sha256}"))
    return findings


def analyze(email: ParsedEmail, source: str = "", intel: ThreatIntel | None = None,
            brands: Mapping[str, tuple[str, ...]] | None = None, model: Model | None = None) -> Report:
    """Analyse a parsed email. ``brands`` adds protected brands for this call;
    ``model`` adds a statistical model's opinion as one more finding."""
    with custom_brands(brands):
        report = _analyze(email, source, intel)
    if model is not None:
        report.findings = sort_findings(report.findings + [_model_finding(model, email)])
    return report


def _model_finding(model: Model, email: ParsedEmail) -> Finding:
    probability, words = model.assess(email)
    evidence = (f"strongest words: {', '.join(repr(w) for w in words)}; " if words else "") + \
        f"threshold {model.threshold:.0%}"
    if probability >= model.threshold:
        return Finding("model.phishing_like", "high",
                       f"A statistical model rates the wording {probability:.0%} phishing-like", evidence)
    return Finding("model.score", "info",
                   f"A statistical model rates the wording {probability:.0%} phishing-like, below its threshold",
                   evidence)


def _analyze(email: ParsedEmail, source: str, intel: ThreatIntel | None) -> Report:
    intel = intel or OfflineIntel()  # week 2: reputation lookups plug in here
    html_links, visible_html_text = parse_html(email.html) if email.html else ([], "")
    html_urls = {link.url for link in html_links}
    links = html_links + [l for l in extract_text_links(email.text)
                          if l.url not in html_urls]
    auth = parse_authentication_results(email.authentication_results)
    # The From domain, when recorded SPF, DKIM and DMARC all passed without
    # authentication or parsing warnings.
    trusted = (email.sender.domain if email.sender and email.sender.domain and auth
               and (auth.spf, auth.dkim, auth.dmarc) == ("pass", "pass", "pass")
               and not auth.warnings and not email.parsing_warnings else "")
    content = _content_findings(email, visible_html_text)
    attachments = _attachment_findings(email, visible_html_text)
    provider = (None if any(f.severity in ("medium", "high") for f in content + attachments)
                else _mailing_context(email, auth))
    sender_domain = email.sender.domain if email.sender else ""
    headers = _header_findings(email, provider, trusted)
    if provider and any(f.severity in ("medium", "high") and f.code != "header.reply_to_mismatch"
                        for f in headers):
        provider = None
        headers = _header_findings(email, trusted_sender=trusted)
    link_findings = _link_findings(links, provider, sender_domain, trusted)
    if provider and any(f.severity in ("medium", "high") for f in link_findings):
        # Forms and other substantial URL signals invalidate routing context
        # for the whole message, irrespective of link order or shared hosts.
        provider = None
        headers = _header_findings(email, trusted_sender=trusted)
        link_findings = _link_findings(links, sender_domain=sender_domain, trusted_sender=trusted)
    # The help-desk Reply-To reduction, like the mailing-route ones, only
    # applies to an otherwise clean message.
    others = content + attachments + link_findings + [f for f in headers if f.code != "header.reply_to_mismatch"]
    if trusted and any(f.severity in ("medium", "high") for f in others):
        headers = _header_findings(email, provider)
    findings = _auth_findings(auth) + headers + link_findings + content + attachments
    return Report(source=source, email=email, auth=auth, findings=sort_findings(findings), links=links)


def analyze_file(path: str | Path, intel: ThreatIntel | None = None,
                 *, max_bytes: int = DEFAULT_MAX_BYTES,
                 brands: Mapping[str, tuple[str, ...]] | None = None, model: Model | None = None) -> Report:
    return analyze(parse_file(path, max_bytes=max_bytes), source=str(path), intel=intel,
                   brands=brands, model=model)
