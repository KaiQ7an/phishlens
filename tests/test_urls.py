from phishlens.urls import Link, extract_text_links, parse_html, strip_urls


def test_text_links_drop_trailing_punctuation():
    links = extract_text_links("Visit https://example.org/a, or www.example.net/b. 详情见 https://example.com/c。")
    assert [l.url for l in links] == ["https://example.org/a", "http://www.example.net/b", "https://example.com/c"]


def test_html_anchor_text_and_forms():
    links, visible = parse_html(
        '<style>.x{}</style><p>Hi <a href="https://evil.example/x">https://my.monash.edu</a></p>'
        '<a href="mailto:a@b.example">mail</a><form action="https://evil.example/collect"></form>')
    assert [(l.url, l.anchor_text, l.source) for l in links] == [
        ("https://evil.example/x", "https://my.monash.edu", "html"),
        ("https://evil.example/collect", "", "form"),
    ]
    assert ".x{}" not in visible and "Hi" in visible


def test_anchor_mismatch():
    assert Link("https://evil.example/login", "https://my.monash.edu/login").anchor_mismatch() == "my.monash.edu"
    assert Link("https://lms.monash.edu/x", "my.monash.edu").anchor_mismatch() is None
    assert Link("https://evil.example/login", "Click here").anchor_mismatch() is None


def test_userinfo_trick_and_hosts():
    link = Link("https://monash.edu@evil.example/login")
    assert link.has_userinfo
    assert link.host == "evil.example"
    assert link.looks_like_login


def test_strip_urls():
    assert "verify" not in strip_urls("see https://x.example/verify now")
