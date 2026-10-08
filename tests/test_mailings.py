import pytest

from phishlens.mailings import mailing_service, tracking_service


@pytest.mark.parametrize("domain", [
    "ccsend.com", "shared1.ccsend.com", "newsletter.ccsend.com",
    "a.newsletter.ccsend.com", "SHARED1.CCSEND.COM", "shared1.ccsend.com.",
])
def test_constant_contact_sender_structure(domain):
    assert mailing_service(domain) == "Constant Contact"


@pytest.mark.parametrize("domain", [
    "", "example.org", "rs6.net", "constantcontact.com", "203.0.113.5",
    "[2001:db8::1]", "evilccsend.com", "ccsend.com.evil.example",
    "ccsend-com.example", "ccsеnd.com", "ccsend。com", ".ccsend.com",
    "shared..ccsend.com", "shared1.ccsend.com..", "bad_name.ccsend.com",
    "-bad.ccsend.com", "bad-.ccsend.com", "a" * 64 + ".ccsend.com",
    "a." * 123 + "ccsend.com", " shared1.ccsend.com", "shared1.ccsend.com\n",
    "mail@shared1.ccsend.com", "https://shared1.ccsend.com", "ccsend.com:443",
    None, b"ccsend.com", 123,
])
def test_unrelated_lookalike_and_malformed_senders_are_not_recognized(domain):
    assert mailing_service(domain) is None


@pytest.mark.parametrize("url", [
    "https://rs6.net/tn.jsp?f=synthetic-token",
    "https://r20.rs6.net/tn.jsp?f=synthetic-token",
    "https://campaign.cc.rs6.net/tn.jsp?f=synthetic-token&c=sample&ch=sample",
    "HTTPS://R20.RS6.NET:443/tn.jsp?c=sample&f=synthetic%2Dtoken",
    "https://r20.rs6.net./tn.jsp?f=synthetic-token",
    "https://r20.rs6.net/tn.jsp?f=synthetic-token#section",
])
def test_provider_tracking_structure_is_recognized(url):
    assert tracking_service(url, "shared1.ccsend.com") == "Constant Contact"


@pytest.mark.parametrize("sender", [
    "example.org", "rs6.net", "ccsend.com.evil.example", "evilccsend.com", "",
])
def test_tracking_host_requires_the_matching_sender_provider(sender):
    assert tracking_service("https://r20.rs6.net/tn.jsp?f=synthetic-token", sender) is None


@pytest.mark.parametrize("url", [
    "https://evil.example/tn.jsp?f=synthetic-token",
    "https://evilrs6.net/tn.jsp?f=synthetic-token",
    "https://rs6.net.evil.example/tn.jsp?f=synthetic-token",
    "https://r20.rs6.net.evil.example/tn.jsp?f=synthetic-token",
    "https://rs6-net.example/tn.jsp?f=synthetic-token",
    "https://rѕ6.net/tn.jsp?f=synthetic-token",
    "https://r20.rs6。net/tn.jsp?f=synthetic-token",
    "https://K.rs6.net/tn.jsp?f=synthetic-token",
    "https://203.0.113.5/tn.jsp?f=synthetic-token",
    "https://[2001:db8::1]/tn.jsp?f=synthetic-token",
    "https://bad_name.rs6.net/tn.jsp?f=synthetic-token",
    "https://-bad.rs6.net/tn.jsp?f=synthetic-token",
    "https://bad-.rs6.net/tn.jsp?f=synthetic-token",
    "https://.rs6.net/tn.jsp?f=synthetic-token",
    "https://r20..rs6.net/tn.jsp?f=synthetic-token",
    "https://r20.rs6.net../tn.jsp?f=synthetic-token",
    "http://r20.rs6.net/tn.jsp?f=synthetic-token",
    "ftp://r20.rs6.net/tn.jsp?f=synthetic-token",
    "//r20.rs6.net/tn.jsp?f=synthetic-token",
    "https:r20.rs6.net/tn.jsp?f=synthetic-token",
    "https:///r20.rs6.net/tn.jsp?f=synthetic-token",
    "https://user@r20.rs6.net/tn.jsp?f=synthetic-token",
    "https://user:password@r20.rs6.net/tn.jsp?f=synthetic-token",
    "https://@r20.rs6.net/tn.jsp?f=synthetic-token",
    "https://r20.rs6.net@evil.example/tn.jsp?f=synthetic-token",
    "https://r20.rs6.net:80/tn.jsp?f=synthetic-token",
    "https://r20.rs6.net:8443/tn.jsp?f=synthetic-token",
    "https://r20.rs6.net:/tn.jsp?f=synthetic-token",
    "https://r20.rs6.net:0443/tn.jsp?f=synthetic-token",
    "https://r20.rs6.net:invalid/tn.jsp?f=synthetic-token",
    "https://r20.rs6.net:65536/tn.jsp?f=synthetic-token",
    "https://r20.rs6.net:-443/tn.jsp?f=synthetic-token",
    "https://[r20.rs6.net/tn.jsp?f=synthetic-token",
    "https://r20.rs6.net]/tn.jsp?f=synthetic-token",
    "https://r20.rs6.net/tn.jsp/extra?f=synthetic-token",
    "https://r20.rs6.net/TN.jsp?f=synthetic-token",
    "https://r20.rs6.net/./tn.jsp?f=synthetic-token",
    "https://r20.rs6.net/%74n.jsp?f=synthetic-token",
    "https://r20.rs6.net/login?f=synthetic-token",
    "https://r20.rs6.net/tn.jsp",
    "https://r20.rs6.net/tn.jsp?f",
    "https://r20.rs6.net/tn.jsp?f=",
    "https://r20.rs6.net/tn.jsp?f=+",
    "https://r20.rs6.net/tn.jsp?f=%20",
    "https://r20.rs6.net/tn.jsp?F=synthetic-token",
    "https://r20.rs6.net/tn.jsp?c=sample",
    "https://r20.rs6.net/tn.jsp?f=one&f=two",
    "https://r20.rs6.net/tn.jsp?f=one&f=one",
    "https://r20.rs6.net/tn.jsp?f=&f=one",
    "https://r20.rs6.net/tn.jsp?f=one&%66=two",
    "https://r20.rs6.net/tn.jsp?f=one&c=one&c=two",
    "https://r20.rs6.net/tn.jsp?f=one&c=",
    "https://r20.rs6.net/tn.jsp?f=one&ch=",
    "https://r20.rs6.net/tn.jsp?f=one&c=+",
    "https://r20.rs6.net/tn.jsp?f=one&ch=%20",
    "https://r20.rs6.net/tn.jsp?f=one&url=sample",
    "https://r20.rs6.net/tn.jsp?f=one&redirect=sample",
    "https://r20.rs6.net/tn.jsp?f=one&__=sample",
    "https://r20.rs6.net/tn.jsp?f=https://example.org",
    "https://r20.rs6.net/tn.jsp?f=prefix-http://example.org",
    "https://r20.rs6.net/tn.jsp?f=HTTPS%3A%2F%2Fexample.org",
    "https://r20.rs6.net/tn.jsp?f=//example.org",
    "https://r20.rs6.net/tn.jsp?f=%2F%2Fexample.org",
    "https://r20.rs6.net/tn.jsp?f=%20%2F%2Fexample.org",
    "https://r20.rs6.net/tn.jsp?f=%5C%5Cexample.org",
    "https://r20.rs6.net/tn.jsp?f=one&c=https://example.org",
    "https://r20.rs6.net/tn.jsp?f=one&ch=//example.org",
    "https://r20.rs6.net/tn.jsp?f=one&ch=%5Cexample.org",
    "https://r20.rs6.net/tn.jsp?f=one;c=two",
    "https://r20.rs6.net/tn.jsp?f=one&c",
    "https://r20.rs6.net/tn.jsp?f=one&=sample",
    "https://r20.rs6.net/tn.jsp?f=one&",
    "https://r20.rs6.net/tn.jsp?f=one&&c=sample",
    "https://r20.rs6.net/tn.jsp?f=%",
    "https://r20.rs6.net/tn.jsp?f=%2",
    "https://r20.rs6.net/tn.jsp?f=%GG",
    "https://r20.rs6.net/tn.jsp?f=%FF",
    "https://r20.rs6.net/tn.jsp?f=%00",
    "https://r20.rs6.net/tn.jsp?f=one&%00=sample",
    " https://r20.rs6.net/tn.jsp?f=synthetic-token",
    "https://r20.rs6.net/tn.jsp?f=synthetic-token\n",
    "https://r20.rs6.net/tn.jsp?f=synthetic token",
    "https://r20.rs6.net/tn.jsp?f=synthetic\x7ftoken",
    "https://r20.rs6.net/tn.jsp?f=synthetic\\token",
    "https://r20.rs6.net/tn.jsp?f=synthetic%20token",
    "https://r20.rs6.net/tn.jsp?f=synthetic\x9btoken",
    "https://r20.rs6.net/tn.jsp?f=synthetic%E2%80%AEtoken",
    "https://r20.rs6.net\t/tn.jsp?f=synthetic-token",
    "", None, b"https://rs6.net/tn.jsp?f=sample", 123,
])
def test_nonmatching_shapes_ambiguous_query_and_malformed_links_do_not_match(url):
    assert tracking_service(url, "shared1.ccsend.com") is None
