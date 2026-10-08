from phishlens.auth import parse_authentication_results


def test_reads_all_three_verdicts():
    header = ("mx.google.com; dkim=pass header.i=@example.org header.s=s1; "
              "spf=softfail (google.com: domain of transitioning x@y) smtp.mailfrom=y.example; "
              "dmarc=fail (p=REJECT sp=REJECT dis=NONE) header.from=example.org")
    verdicts = parse_authentication_results([header])
    assert (verdicts.spf, verdicts.dkim, verdicts.dmarc) == ("softfail", "pass", "fail")
    assert verdicts.authserv_id == "mx.google.com"


def test_only_the_topmost_header_is_trusted():
    trusted = "mx.receiver.example; spf=fail; dkim=none; dmarc=fail"
    forged_by_sender = "evil.example; spf=pass; dkim=pass; dmarc=pass"
    verdicts = parse_authentication_results([trusted, forged_by_sender])
    assert verdicts.dmarc == "fail"


def test_missing_header_returns_none():
    assert parse_authentication_results([]) is None


def test_missing_method_is_none():
    verdicts = parse_authentication_results(["mx.receiver.example; spf=pass"])
    assert verdicts.dkim is None and verdicts.dmarc is None
