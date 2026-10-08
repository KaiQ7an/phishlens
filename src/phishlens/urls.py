"""Link extraction from plain-text and HTML bodies.

Links are only parsed as strings. PhishLens never fetches, resolves or opens them.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import urlsplit

from .domains import same_site, to_unicode

URL_SHORTENERS = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
    "cutt.ly", "t.ly", "s.id", "rb.gy", "tiny.cc", "shorturl.at", "dwz.cn", "url.cn",
})

_URL_RE = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"'()\[\]{}]+")
_TRAILING = ".,;:!?'\")]}。，；：！？）】」"
_DOMAIN_LIKE_RE = re.compile(r"(?i)^(?:https?://)?((?:[\w-]+\.)+[^\W\d_]{2,})(?:[/:?#]\S*)?$")
_LOGIN_HINT_RE = re.compile(r"(?i)log[-_]?in|sign[-_]?in|verify|password|account|sso|auth")


@dataclass(frozen=True)
class Link:
    url: str
    anchor_text: str = ""
    source: str = "text"  # text | html | form

    def _split(self):
        try:
            return urlsplit(self.url)
        except ValueError:
            return None

    @property
    def host(self) -> str:
        parts = self._split()
        return ((parts.hostname if parts else "") or "").lower().rstrip(".")

    @property
    def scheme(self) -> str:
        parts = self._split()
        return parts.scheme.lower() if parts else ""

    @property
    def has_userinfo(self) -> bool:
        """`https://monash.edu@evil.example/` actually goes to evil.example."""
        parts = self._split()
        return bool(parts and parts.username is not None)

    @property
    def looks_like_login(self) -> bool:
        return bool(_LOGIN_HINT_RE.search(self.url) or _LOGIN_HINT_RE.search(self.anchor_text))

    @property
    def anchor_looks_like_login(self) -> bool:
        """Visible login hints, without treating opaque tracking tokens as prose."""
        return bool(_LOGIN_HINT_RE.search(self.anchor_text))

    def anchor_host(self) -> str | None:
        """The domain the visible link text claims, if the text looks like a URL."""
        match = _DOMAIN_LIKE_RE.match(self.anchor_text.strip())
        return match.group(1).lower() if match else None

    def anchor_mismatch(self) -> str | None:
        """Return the claimed host when the visible text points somewhere else."""
        claimed = self.anchor_host()
        if claimed and self.host and not same_site(claimed, self.host):
            return claimed
        return None

    def display_host(self) -> str:
        unicode_host = to_unicode(self.host)
        return f"{unicode_host} ({self.host})" if unicode_host != self.host else self.host


def _clean(url: str) -> str:
    url = url.rstrip(_TRAILING)
    return "http://" + url if url.lower().startswith("www.") else url


def strip_urls(text: str) -> str:
    """Remove URLs so keyword checks only see the words a person reads."""
    return _URL_RE.sub(" ", text)


def extract_text_links(text: str) -> list[Link]:
    links: list[Link] = []
    seen: set[str] = set()
    for match in _URL_RE.finditer(text):
        url = _clean(match.group(0))
        if url not in seen:
            seen.add(url)
            links.append(Link(url))
    return links


class _HTMLCollector(HTMLParser):
    _BLOCK_TAGS = {"br", "p", "div", "tr", "li", "h1", "h2", "h3", "table"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[Link] = []
        self.text: list[str] = []
        self._href: str | None = None
        self._anchor: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if tag in ("script", "style"):
            self._skip += 1
        elif tag == "a" and attributes.get("href"):
            self._href = attributes["href"]
            self._anchor = []
        elif tag == "form" and attributes.get("action"):
            self.links.append(Link(attributes["action"], "", "form"))
        if tag in self._BLOCK_TAGS:
            self.text.append("\n")

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip:
            self._skip -= 1
        elif tag == "a" and self._href is not None:
            if self._href.lstrip().lower().startswith(("http://", "https://")):
                self.links.append(Link(self._href, " ".join("".join(self._anchor).split()), "html"))
            self._href = None

    def handle_data(self, data):
        if self._skip:
            return
        self.text.append(data)
        if self._href is not None:
            self._anchor.append(data)


def parse_html(html: str) -> tuple[list[Link], str]:
    """Return the links in an HTML body and its visible text."""
    collector = _HTMLCollector()
    collector.feed(html)
    collector.close()
    return collector.links, "".join(collector.text)
