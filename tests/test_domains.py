import pytest

from phishlens.domains import (find_lookalike, is_government, is_ip, is_mixed_script,
                               registrable_domain, same_site, to_unicode)

LOOKALIKE = "mоnash.edu".encode("idna").decode("ascii")


@pytest.mark.parametrize("host, expected", [
    ("my.monash.edu", "monash.edu"),
    ("www.commbank.com.au", "commbank.com.au"),
    ("ato.gov.au", "ato.gov.au"),
    ("a.b.example.co.uk", "example.co.uk"),
    ("localhost", "localhost"),
])
def test_registrable_domain(host, expected):
    assert registrable_domain(host) == expected


def test_punycode_is_decoded_to_reveal_lookalike_characters():
    assert LOOKALIKE.startswith("xn--")
    assert to_unicode(LOOKALIKE) == "mоnash.edu"
    assert to_unicode(LOOKALIKE) != "monash.edu"


@pytest.mark.parametrize("host, imitates, technique", [
    (LOOKALIKE, "monash.edu", "homoglyph"),
    ("rnonash.edu", "monash.edu", "homoglyph"),
    ("paypa1.com", "paypal.com", "homoglyph"),
    ("monash.edu.verify-login.example", "monash.edu", "brand-in-subdomain"),
    ("monash.com", "monash.edu", "tld-swap"),
    ("monsh.edu", "monash.edu", "typosquat"),
    ("monash-account-verify.example", "monash.edu", "brand-keyword"),
])
def test_lookalikes_are_detected(host, imitates, technique):
    result = find_lookalike(host)
    assert result is not None
    assert (result.imitates, result.technique) == (imitates, technique)


@pytest.mark.parametrize("host", [
    "monash.edu", "my.monash.edu", "lms.monash.edu", "example.org",
    "pineapple.com", "officeworks.com.au", "203.0.113.5",
])
def test_legitimate_and_unrelated_domains_are_not_flagged(host):
    assert find_lookalike(host) is None


def test_mixed_script():
    assert is_mixed_script(LOOKALIKE)
    assert not is_mixed_script("monash.edu")
    assert not is_mixed_script("例子.example")


def test_ip_and_government_checks():
    assert is_ip("203.0.113.45") and is_ip("[2001:db8::1]")
    assert not is_ip("monash.edu")
    assert is_government("ato.gov.au") and is_government("mfa.gov.cn")
    assert not is_government("cn-consulate-service.example")
    assert not is_government("gov.example")


def test_same_site_ignores_subdomains():
    assert same_site("mail.example.org", "example.org")
    assert not same_site("example.org", "example.net")
