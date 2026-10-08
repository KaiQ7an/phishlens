"""Turn a parsed email into a scored, explained report."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from . import attachments as attachment_rules
from .auth import AuthVerdicts, parse_authentication_results
from .content import find_signals
from .domains import (PROTECTED_BRANDS, PROTECTED_DOMAINS, find_lookalike, is_government, is_ip,
                      is_mixed_script, same_site, to_unicode)
from .intel import OfflineIntel, ThreatIntel
from .mailings import mailing_service, tracking_service
from .message import DEFAULT_MAX_BYTES, Attachment, ParsedEmail, parse_file
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


def _header_findings(email: ParsedEmail, provider: str | None = None) -> list[Finding]:
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
    for brand, domains in PROTECTED_BRANDS.items():
        if re.search(rf"\b{re.escape(brand)}\b", name) and not any(same_site(sender.domain, d) for d in domains):
            findings.append(Finding("header.display_name_brand", "high",
                                    f"The display name says '{brand.title()}' but the address is not one of its domains",
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
        context = provider and not malformed and all(_ordinary_reply_domain(r.domain) for r in replies)
        title = (f"Replies use a different domain from a {provider} sender address; this can occur with From rewriting"
                 if context else "Replies go to a different domain from the sender")
        findings.append(Finding("header.reply_to_mismatch", "low" if context else "medium", title,
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
                   sender_domain: str = "") -> list[Finding]:
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
                             and not any(same_site(claimed, domain) for domain in PROTECTED_DOMAINS)
                             and find_lookalike(claimed) is None and not is_mixed_script(claimed)
                             and tracking_service(link.url, sender_domain) == provider)
            if route_context:
                # Separate codes prevent a low routing warning from deduping
                # away a later high mismatch to the same intermediary host.
                add("url.tracking_destination_unverified", "low",
                    f"Link text shows {claimed} via a {provider} tracking route; final destination is unverified",
                    link.url, host)
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


def _content_findings(email: ParsedEmail, visible_html_text: str) -> list[Finding]:
    text = strip_urls("\n".join((email.subject, email.text, visible_html_text)))
    findings = []
    for signal, matched in find_signals(text):
        evidence = ", ".join(f"'{m}'" for m in matched[:5])
        if signal.code == "content.authority" and email.sender and not is_government(email.sender.domain):
            findings.append(Finding("content.authority_non_gov", "high",
                                    "Claims to be police or government but was not sent from a government domain",
                                    f"{evidence}; sender {email.sender.domain}"))
        else:
            findings.append(Finding(signal.code, signal.severity, signal.title, evidence))
    return findings


def _attachment_findings(email: ParsedEmail) -> list[Finding]:
    findings = []
    for attachment in email.attachments:
        for severity, code, explanation in attachment_rules.classify(attachment):
            findings.append(Finding(code, severity, explanation, f"sha256 {attachment.sha256}"))
    return findings


def analyze(email: ParsedEmail, source: str = "", intel: ThreatIntel | None = None) -> Report:
    intel = intel or OfflineIntel()  # week 2: reputation lookups plug in here
    html_links, visible_html_text = parse_html(email.html) if email.html else ([], "")
    html_urls = {link.url for link in html_links}
    links = html_links + [l for l in extract_text_links(email.text)
                          if l.url not in html_urls]
    auth = parse_authentication_results(email.authentication_results)
    content = _content_findings(email, visible_html_text)
    attachments = _attachment_findings(email)
    provider = (None if any(f.severity in ("medium", "high") for f in content + attachments)
                else _mailing_context(email, auth))
    headers = _header_findings(email, provider)
    if provider and any(f.severity in ("medium", "high") and f.code != "header.reply_to_mismatch"
                        for f in headers):
        provider = None
        headers = _header_findings(email)
    findings = (_auth_findings(auth) + headers
                + _link_findings(links, provider, email.sender.domain if email.sender else "")
                + content + attachments)
    return Report(source=source, email=email, auth=auth, findings=sort_findings(findings), links=links)


def analyze_file(path: str | Path, intel: ThreatIntel | None = None,
                 *, max_bytes: int = DEFAULT_MAX_BYTES) -> Report:
    return analyze(parse_file(path, max_bytes=max_bytes), source=str(path), intel=intel)
