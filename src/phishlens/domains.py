"""Domain analysis: registrable domains, IDN decoding and lookalike detection.

The registrable-domain logic uses a small built-in list of multi-level public
suffixes instead of the full Public Suffix List, so PhishLens stays offline and
dependency-free. It covers the suffixes common in Australian and Chinese mail;
an unknown multi-level suffix falls back to the last two labels.
"""

from __future__ import annotations

import ipaddress
import json
import re
import unicodedata
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path

MULTI_LEVEL_SUFFIXES = frozenset({
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au",
    "co.uk", "org.uk", "ac.uk", "gov.uk",
    "co.nz", "org.nz", "ac.nz", "govt.nz",
    "com.cn", "net.cn", "org.cn", "edu.cn", "gov.cn",
    "com.hk", "edu.hk", "gov.hk", "com.sg", "edu.sg", "gov.sg",
    "co.jp", "ac.jp", "go.jp",
})

# Brands whose names phishers borrow, with the domains that legitimately send for them.
PROTECTED_BRANDS: dict[str, tuple[str, ...]] = {
    "monash": ("monash.edu",),
    "microsoft": ("microsoft.com", "office.com", "outlook.com", "live.com", "sharepointonline.com"),
    "google": ("google.com", "gmail.com"),
    "apple": ("apple.com", "icloud.com"),
    "paypal": ("paypal.com",),
    "commbank": ("commbank.com.au",),
    "auspost": ("auspost.com.au",),
    "mygov": ("my.gov.au",),
    "facebook": ("facebook.com", "facebookmail.com", "meta.com", "fb.com"),
    "instagram": ("instagram.com",),
    "docusign": ("docusign.com", "docusign.net"),
}
# Product names that stand for a protected brand in display names and domains.
BRAND_ALIASES: dict[str, tuple[str, ...]] = {
    "microsoft": ("sharepoint", "onedrive", "office 365", "microsoft 365"),
    "auspost": ("australia post",),
    "facebook": ("meta",),  # too short for domain tokens; used for display names only
}


def brand_terms(brand: str) -> tuple[str, ...]:
    return (brand,) + BRAND_ALIASES.get(brand, ())


PROTECTED_DOMAINS = frozenset(d for domains in PROTECTED_BRANDS.values() for d in domains)

# Brands a user adds for one analysis (phishlens analyze --brands FILE). They
# extend the built-in list only inside custom_brands(), so separate analyses
# in one process cannot leak brands into each other.
_CUSTOM_BRANDS: ContextVar[Mapping[str, tuple[str, ...]]] = ContextVar("custom_brands", default={})
MAX_BRAND_FILE_BYTES = 64 * 1024
_BRAND_NAME_RE = re.compile(r"[a-z0-9][a-z0-9 ]{2,39}")
_ASCII_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


@contextmanager
def custom_brands(brands: Mapping[str, tuple[str, ...]] | None) -> Iterator[None]:
    token = _CUSTOM_BRANDS.set(dict(brands or {}))
    try:
        yield
    finally:
        _CUSTOM_BRANDS.reset(token)


def protected_brands() -> dict[str, tuple[str, ...]]:
    custom = _CUSTOM_BRANDS.get()
    if not custom:
        return PROTECTED_BRANDS
    merged = dict(PROTECTED_BRANDS)
    for brand, domains in custom.items():
        merged[brand] = tuple(dict.fromkeys(merged.get(brand, ()) + tuple(domains)))
    return merged


def protected_domains() -> frozenset[str]:
    if not _CUSTOM_BRANDS.get():
        return PROTECTED_DOMAINS
    return frozenset(d for domains in protected_brands().values() for d in domains)


def load_brand_file(path: str | Path) -> dict[str, tuple[str, ...]]:
    """Read {"brand name": ["domain", ...]} from a small JSON file.

    Raises ValueError with a readable reason. Domains must be registrable
    domains (example.com, example.com.au), not subdomains, IP addresses or URLs.
    """
    with open(path, "rb") as handle:
        data = handle.read(MAX_BRAND_FILE_BYTES + 1)
    if len(data) > MAX_BRAND_FILE_BYTES:
        raise ValueError(f"file is larger than {MAX_BRAND_FILE_BYTES // 1024} KiB")
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"not valid UTF-8 JSON ({error})") from error
    if not isinstance(value, dict) or not value:
        raise ValueError('expected an object such as {"acme": ["acme.com"]}')
    if len(value) > 100:
        raise ValueError("at most 100 brands are supported")
    brands: dict[str, tuple[str, ...]] = {}
    for raw_name, raw_domains in value.items():
        name = " ".join(str(raw_name).lower().split())
        if not _BRAND_NAME_RE.fullmatch(name):
            raise ValueError(f"brand name {raw_name!r} must be 3-40 letters, digits or spaces")
        if (not isinstance(raw_domains, list) or not 1 <= len(raw_domains) <= 20
                or not all(isinstance(d, str) for d in raw_domains)):
            raise ValueError(f"brand {name!r} needs a list of 1-20 domain names")
        domains = []
        for raw in raw_domains:
            domain = raw.strip().lower().rstrip(".")
            labels = domain.split(".")
            if (len(domain) > 253 or len(labels) < 2 or is_ip(domain)
                    or not all(_ASCII_LABEL_RE.fullmatch(label) for label in labels)
                    or registrable_domain(domain) != domain):
                raise ValueError(f"{raw!r} for brand {name!r} is not a registrable domain such as example.com")
            domains.append(domain)
        brands[name] = tuple(dict.fromkeys(domains))
    return brands

GOVERNMENT_SUFFIXES = ("gov", "mil", "gov.au", "gov.cn", "gov.uk", "govt.nz", "gov.hk", "gov.sg", "go.jp")

# Characters commonly swapped in for Latin letters. Not exhaustive; Unicode's
# confusables table is far larger, but these cover most real-world lookalikes.
_CONFUSABLES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i",
    "ј": "j", "ѕ": "s", "ԁ": "d", "ӏ": "l", "һ": "h", "ԛ": "q", "ԝ": "w",
    "ο": "o", "α": "a", "ν": "v", "ι": "i", "κ": "k", "τ": "t", "ρ": "p",
    "0": "o", "1": "l", "3": "e", "5": "s",
}


def to_unicode(host: str) -> str:
    """Decode punycode labels (xn--...) so lookalike characters become visible."""
    labels = []
    for label in host.lower().strip(".").split("."):
        if label.startswith("xn--"):
            try:
                label = label.encode("ascii").decode("idna")
            except UnicodeError:
                pass
        labels.append(label)
    return ".".join(labels)


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def _split(domain: str) -> tuple[str, str]:
    """Split a registrable domain into (name label, public suffix)."""
    labels = domain.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_LEVEL_SUFFIXES:
        return labels[-3], ".".join(labels[-2:])
    if len(labels) >= 2:
        return labels[-2], labels[-1]
    return domain, ""


def registrable_domain(host: str) -> str:
    labels = host.lower().strip(".").split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_LEVEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def same_site(host_a: str, host_b: str) -> bool:
    return registrable_domain(to_unicode(host_a)) == registrable_domain(to_unicode(host_b))


def is_government(host: str) -> bool:
    host = to_unicode(host)
    return any(host == suffix or host.endswith("." + suffix) for suffix in GOVERNMENT_SUFFIXES)


def skeleton(text: str) -> str:
    """Reduce text to the shape a reader sees: lookalike characters become ASCII."""
    text = unicodedata.normalize("NFKC", text).lower()
    text = "".join(_CONFUSABLES.get(ch, ch) for ch in text)
    return text.replace("rn", "m").replace("vv", "w")


def _script(ch: str) -> str:
    name = unicodedata.name(ch, "")
    return name.split(" ", 1)[0] if name else "UNKNOWN"


def is_mixed_script(host: str) -> bool:
    """True when one label mixes alphabets, e.g. Latin letters with a Cyrillic 'о'."""
    for label in to_unicode(host).split("."):
        scripts = {_script(ch) for ch in label if ch.isalpha()}
        if len(scripts) > 1:
            return True
    return False


def edit_distance(a: str, b: str) -> int:
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb)))
        previous = current
    return previous[-1]


@dataclass(frozen=True)
class Lookalike:
    imitates: str
    technique: str  # homoglyph | brand-in-subdomain | tld-swap | typosquat | brand-keyword


def find_lookalike(host: str) -> Lookalike | None:
    """Return the protected domain this host imitates, or None."""
    uhost = to_unicode(host)
    if not uhost or is_ip(uhost):
        return None
    reg = registrable_domain(uhost)
    protected = protected_domains()
    if reg in protected:
        return None

    reg_skeleton = skeleton(reg)
    legit_domains = sorted(protected)
    for legit in legit_domains:
        if reg_skeleton == skeleton(legit):
            return Lookalike(legit, "homoglyph")
    for legit in legit_domains:
        if f".{legit}." in f".{uhost}.":
            return Lookalike(legit, "brand-in-subdomain")

    name, suffix = _split(reg)
    for legit in legit_domains:
        legit_name, legit_suffix = _split(legit)
        if name == legit_name and suffix != legit_suffix:
            return Lookalike(legit, "tld-swap")
        if len(legit_name) >= 4 and edit_distance(skeleton(name), legit_name) == 1:
            return Lookalike(legit, "typosquat")
    tokens = set(name.split("-"))
    for brand, domains in protected_brands().items():
        terms = [term.replace(" ", "") for term in brand_terms(brand)]
        if any(len(term) >= 5 and term in tokens for term in terms):
            return Lookalike(domains[0], "brand-keyword")
    return None
