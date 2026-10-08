"""Domain analysis: registrable domains, IDN decoding and lookalike detection.

The registrable-domain logic uses a small built-in list of multi-level public
suffixes instead of the full Public Suffix List, so PhishLens stays offline and
dependency-free. It covers the suffixes common in Australian and Chinese mail;
an unknown multi-level suffix falls back to the last two labels.
"""

from __future__ import annotations

import ipaddress
import unicodedata
from dataclasses import dataclass

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
    "microsoft": ("microsoft.com", "office.com", "outlook.com", "live.com"),
    "google": ("google.com", "gmail.com"),
    "apple": ("apple.com", "icloud.com"),
    "paypal": ("paypal.com",),
    "commbank": ("commbank.com.au",),
    "auspost": ("auspost.com.au",),
    "mygov": ("my.gov.au",),
}
PROTECTED_DOMAINS = frozenset(d for domains in PROTECTED_BRANDS.values() for d in domains)

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
    if reg in PROTECTED_DOMAINS:
        return None

    reg_skeleton = skeleton(reg)
    legit_domains = sorted(PROTECTED_DOMAINS)
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
    for brand, domains in PROTECTED_BRANDS.items():
        if len(brand) >= 5 and brand in tokens:
            return Lookalike(domains[0], "brand-keyword")
    return None
