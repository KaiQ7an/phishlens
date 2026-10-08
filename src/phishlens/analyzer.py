"""Turn a parsed email into a scored, explained report."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from . import attachments as attachment_rules
from .auth import AuthVerdicts, parse_authentication_results
from .content import find_signals
from .domains import (PROTECTED_BRANDS, find_lookalike, is_government, is_ip,
                      is_mixed_script, same_site, to_unicode)
from .intel import OfflineIntel, ThreatIntel
from .message import DEFAULT_MAX_BYTES, Attachment, ParsedEmail, parse_file
from .scoring import Finding, risk_level, sort_findings, total_score
from .urls import URL_SHORTENERS, Link, extract_text_links, parse_html, strip_urls

_EMAIL_IN_TEXT_RE = re.compile(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)")

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
                                "DMARC failed: the domain in From did not authorise this message",
                                f"dmarc={auth.dmarc}"))
    if auth.spf == "fail":
        findings.append(Finding("auth.spf_fail", "medium",
                                "SPF failed: the sending server is not allowed to send for this domain",
                                f"spf={auth.spf}"))
    elif auth.spf == "softfail":
        findings.append(Finding("auth.spf_softfail", "low",
                                "SPF soft-failed: the sending server is probably not authorised",
                                f"spf={auth.spf}"))
    if auth.dkim == "fail":
        findings.append(Finding("auth.dkim_fail", "medium",
                                "DKIM failed: the message was altered or the signature is forged",
                                f"dkim={auth.dkim}"))
    elif auth.dkim in (None, "none"):
        findings.append(Finding("auth.dkim_missing", "low", "The message is not DKIM-signed",
                                f"dkim={auth.dkim or 'missing'}"))
    return findings


def _header_findings(email: ParsedEmail) -> list[Finding]:
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

    for reply in email.reply_to:
        if reply.domain and not same_site(reply.domain, sender.domain):
            findings.append(Finding("header.reply_to_mismatch", "medium",
                                    "Replies go to a different domain from the sender",
                                    f"From {sender.domain}, Reply-To {reply.address}"))
            break
    if email.return_path and "@" in email.return_path:
        bounce_domain = email.return_path.rpartition("@")[2]
        if not same_site(bounce_domain, sender.domain):
            findings.append(Finding("header.return_path_mismatch", "info",
                                    "Bounces go to a different domain (common for mailing services)",
                                    f"Return-Path {email.return_path}"))
    return findings


def _link_findings(links: list[Link]) -> list[Finding]:
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
    links = html_links + [l for l in extract_text_links(email.text)
                          if l.url not in {h.url for h in html_links}]
    auth = parse_authentication_results(email.authentication_results)
    findings = (_auth_findings(auth) + _header_findings(email) + _link_findings(links)
                + _content_findings(email, visible_html_text) + _attachment_findings(email))
    return Report(source=source, email=email, auth=auth, findings=sort_findings(findings), links=links)


def analyze_file(path: str | Path, intel: ThreatIntel | None = None,
                 *, max_bytes: int = DEFAULT_MAX_BYTES) -> Report:
    return analyze(parse_file(path, max_bytes=max_bytes), source=str(path), intel=intel)
