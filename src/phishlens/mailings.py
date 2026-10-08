"""Recognize a narrow mailing-service pattern without making a trust decision.

Constant Contact documents its shared ``ccsend.com`` From domain and ``rs6.net``
campaign infrastructure. Its support community describes ``r20`` links as
intermediate click-tracking URLs and shows the ``/tn.jsp?f=...`` route. This is
only structural context: a match does not authenticate mail, verify a tracking
token, identify its final destination, or establish that any content is safe.

Sources:
https://knowledgebase.constantcontact.com/email-digital-marketing/articles/KnowledgeBase/53013-Customize-the-subdomain-for-your-From-email-address
https://knowledgebase.constantcontact.com/email-digital-marketing/articles/KnowledgeBase/5800-Safelist-Constant-Contact-web-domains-in-a-security-program
https://community.constantcontact.com/t5/Product-Ideas/Turn-off-link-tracking-in-campaigns/idi-p/334097
"""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlsplit

_CONSTANT_CONTACT = "Constant Contact"
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_DOMAIN_RE = re.compile(rf"{_LABEL}(?:\.{_LABEL})*", re.ASCII)
_BAD_ESCAPE_RE = re.compile(r"%(?![a-fA-F0-9]{2})")
_URL_VALUE_RE = re.compile(r"https?://", re.IGNORECASE)


def _domain(value: str) -> str | None:
    """Accept ASCII DNS names, including one optional DNS root dot."""
    if not isinstance(value, str) or not value.isascii():
        return None
    domain = value.lower().removesuffix(".")
    if len(domain) > 253 or not _DOMAIN_RE.fullmatch(domain):
        return None
    return domain


def _belongs_to(domain: str, suffix: str) -> bool:
    return domain == suffix or domain.endswith("." + suffix)


def mailing_service(sender_domain: str) -> str | None:
    """Return structural provider context for a sender domain, without trust."""
    domain = _domain(sender_domain)
    if domain and _belongs_to(domain, "ccsend.com"):
        return _CONSTANT_CONTACT
    return None


def tracking_service(url: str, sender_domain: str) -> str | None:
    """Recognize a matching provider's opaque route without inferring its target.

    Require HTTPS, the documented host family, the exact route, no credentials,
    an absent port or explicit 443, and one nonblank ``f`` query parameter.
    Only nonblank ``f``, ``c``, and ``ch`` values are recognized; obvious URLs,
    malformed syntax, and repeated decoded query keys remain outside the pattern.
    """
    provider = mailing_service(sender_domain)
    if not provider or not isinstance(url, str) or not url.isascii():
        return None
    # urlsplit removes some controls and leading whitespace; reject these before
    # parsing so malformed inputs cannot turn into a recognized URL.
    if any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in url):
        return None
    if "\\" in url or _BAD_ESCAPE_RE.search(url):
        return None
    try:
        parts = urlsplit(url)
        if not parts.netloc.isascii():
            return None
        host = _domain(parts.hostname or "")
        if (parts.scheme != "https" or not host or not _belongs_to(host, "rs6.net")
                or parts.username is not None or parts.password is not None
                or parts.port not in (None, 443) or parts.path != "/tn.jsp"):
            return None
        # Empty ports and noncanonical port spellings are outside this pattern.
        if ":" in parts.netloc and not parts.netloc.endswith(":443"):
            return None
        # Semicolons can be treated as separators by other query parsers.
        if ";" in parts.query:
            return None
        query = parse_qsl(parts.query, keep_blank_values=True, strict_parsing=True,
                          errors="strict", max_num_fields=3)
    except (ValueError, UnicodeError):
        return None
    values: dict[str, str] = {}
    for key, value in query:
        if (key not in {"f", "c", "ch"} or key in values or not value
                or not value.isascii()
                or any(ord(ch) <= 32 or ord(ch) == 127 for ch in key + value)
                or _URL_VALUE_RE.search(value) or value.lstrip().startswith("//")
                or "\\" in value):
            return None
        values[key] = value
    return provider if "f" in values else None
