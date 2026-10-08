import pytest

from phishlens.auth import parse_authentication_results


def test_reads_all_three_verdicts():
    header = ("mx.google.com; dkim=pass header.i=@example.org header.s=s1; "
              "spf=softfail (google.com: domain of transitioning x@y) smtp.mailfrom=y.example; "
              "dmarc=fail (p=REJECT sp=REJECT dis=NONE) header.from=example.org")
    verdicts = parse_authentication_results([header])
    assert (verdicts.spf, verdicts.dkim, verdicts.dmarc) == ("softfail", "pass", "fail")
    assert verdicts.authserv_id == "mx.google.com"


def test_only_the_topmost_header_is_read():
    topmost = "mx.receiver.example; spf=fail; dkim=none; dmarc=fail"
    forged_by_sender = "evil.example; spf=pass; dkim=pass; dmarc=pass"
    verdicts = parse_authentication_results([topmost, forged_by_sender])
    assert verdicts.dmarc == "fail"


def test_missing_header_returns_none():
    assert parse_authentication_results([]) is None


def test_missing_method_is_none():
    verdicts = parse_authentication_results(["mx.receiver.example; spf=pass"])
    assert verdicts.dkim is None and verdicts.dmarc is None


@pytest.mark.parametrize("comment", [
    "(spf=pass; dkim=pass; dmarc=pass)",
    "(outer (spf=pass; (dkim=pass)) dmarc=pass)",
    r"(escaped \) spf=pass; dkim=pass; \( dmarc=pass)",
    '(literal "quote" spf=pass; dkim=pass; dmarc=pass)',
])
def test_fake_results_inside_comments_do_not_override_real_failures(comment):
    verdicts = parse_authentication_results([
        f"mx.receiver.example {comment}; spf=fail; dkim=fail; dmarc=fail"
    ])
    assert (verdicts.spf, verdicts.dkim, verdicts.dmarc) == ("fail", "fail", "fail")
    assert verdicts.authserv_id == "mx.receiver.example"
    assert not verdicts.warnings


def test_comments_can_appear_between_method_tokens():
    verdicts = parse_authentication_results([
        "(receiver) mx.receiver.example (version) 1; "
        "spf (comment) / (method version) 1 (comment) = (comment) pass (ok); "
        "dkim=fail; dmarc=fail"
    ])
    assert verdicts.spf == "pass"
    assert verdicts.authserv_id == "mx.receiver.example"
    assert not verdicts.warnings


def test_quoted_authserv_id_is_only_a_service_label():
    verdicts = parse_authentication_results([
        '"spf=pass; dkim=pass; dmarc=pass" 1; spf=fail; dkim=fail; dmarc=fail'
    ])
    assert verdicts.authserv_id == "spf=pass; dkim=pass; dmarc=pass"
    assert (verdicts.spf, verdicts.dkim, verdicts.dmarc) == ("fail", "fail", "fail")
    assert not verdicts.warnings


def test_quoted_reason_and_properties_cannot_introduce_method_clauses():
    verdicts = parse_authentication_results([
        'mx.receiver.example; spf=fail reason="dkim=pass; dmarc=pass" '
        'smtp.mailfrom="x; dkim=pass; dmarc=pass"@example.org; '
        'dkim=fail header.i="dmarc=pass; spf=pass"; dmarc=fail'
    ])
    assert (verdicts.spf, verdicts.dkim, verdicts.dmarc) == ("fail", "fail", "fail")
    assert not verdicts.warnings


def test_escaped_quotes_and_parentheses_in_reason_are_not_comment_boundaries():
    verdicts = parse_authentication_results([
        r'mx.receiver.example; spf=fail reason="say \"hello\" (spf=pass; dkim=pass)"; '
        "dkim=fail; dmarc=fail"
    ])
    assert (verdicts.spf, verdicts.dkim, verdicts.dmarc) == ("fail", "fail", "fail")
    assert not verdicts.warnings


def test_folded_uppercase_and_versioned_methods():
    verdicts = parse_authentication_results([
        "MX.receiver.example 1;\r\n\tSPF / 1 = PASS smtp.mailfrom=example.org;\r\n "
        "DKIM/1=PERMERROR; DMARC=FAIL"
    ])
    assert (verdicts.spf, verdicts.dkim, verdicts.dmarc) == ("pass", "permerror", "fail")
    assert verdicts.authserv_id == "MX.receiver.example"
    assert not verdicts.warnings


@pytest.mark.parametrize("clause", [
    'reason="spf=pass"',
    "header.spf=pass",
    "x-spf=pass",
    "spf=pass!",
    '"spf"=pass',
    "spf=pass dmarc=pass",
    "spf/=pass",
    "spf/foo=pass",
    "spf=pass reason=spf=pass",
    'spf=pass reason="ok"garbage',
])
def test_only_complete_method_clauses_provide_verdicts(clause):
    verdicts = parse_authentication_results([
        f"mx.receiver.example; {clause}; dmarc=fail"
    ])
    assert verdicts.spf is None
    assert verdicts.dkim is None
    assert verdicts.dmarc == "fail"


def test_unknown_well_formed_method_is_ignored_without_hiding_known_results():
    verdicts = parse_authentication_results([
        "mx.receiver.example; iprev=pass policy.iprev=192.0.2.1; dmarc=fail"
    ])
    assert verdicts.dmarc == "fail"
    assert not verdicts.warnings


def test_identical_repeated_methods_collapse_to_one_verdict():
    verdicts = parse_authentication_results([
        "mx.receiver.example; dkim=pass header.d=first.example; "
        "DKIM=PASS header.d=second.example"
    ])
    assert verdicts.dkim == "pass"
    assert not verdicts.warnings


@pytest.mark.parametrize("results", ["pass; dkim=fail", "fail; dkim=pass", "pass; dkim=fail; dkim=pass"])
def test_conflicting_repeated_methods_are_unknown_and_reported(results):
    verdicts = parse_authentication_results([
        f"mx.receiver.example; dkim={results}; spf=fail"
    ])
    assert verdicts.dkim is None
    assert verdicts.spf == "fail"
    assert any("Conflicting DKIM" in warning for warning in verdicts.warnings)


@pytest.mark.parametrize("clauses", [
    "spf=pass; spf=fail!",
    "spf=fail!; spf=pass",
    'spf=pass; spf=fail reason="ok" unexpected=value',
])
def test_malformed_duplicate_cannot_leave_an_unambiguous_passing_verdict(clauses):
    verdicts = parse_authentication_results([f"mx.receiver.example; {clauses}; dmarc=fail"])
    assert verdicts.spf is None
    assert verdicts.dmarc == "fail"
    assert verdicts.warnings


@pytest.mark.parametrize("header", [
    "mx.receiver.example; spf=pass (unterminated; dmarc=fail",
    'mx.receiver.example; spf=pass reason="unterminated; dmarc=fail',
    "mx.receiver.example; spf=pass ) ; dmarc=fail",
    "mx.receiver.example; spf=pass (escaped closing\\)",
    "mx.receiver.example; spf=pass\\; dmarc=fail",
    "mx.receiver.example; spf=pass\x00; dmarc=fail",
    "mx.receiver.example; spf=pass\n; dmarc=fail",
    "spf=pass; dmarc=pass",
    "mx.receiver.example extra; dmarc=pass",
    "mx.receiver.example",
    "",
])
def test_ambiguous_or_invalid_header_is_not_recovered_into_passing_verdicts(header):
    verdicts = parse_authentication_results([
        header, "lower.example; spf=pass; dkim=pass; dmarc=pass"
    ])
    assert (verdicts.spf, verdicts.dkim, verdicts.dmarc) == (None, None, None)
    assert verdicts.warnings


def test_none_is_a_valid_no_authentication_result():
    verdicts = parse_authentication_results(["mx.receiver.example 1; (no tests) none"])
    assert (verdicts.spf, verdicts.dkim, verdicts.dmarc) == (None, None, None)
    assert verdicts.authserv_id == "mx.receiver.example"
    assert not verdicts.warnings


def test_none_cannot_be_mixed_with_method_results():
    verdicts = parse_authentication_results(["mx.receiver.example; none; spf=pass"])
    assert verdicts.spf is None
    assert verdicts.warnings


def test_malformed_supporting_values_are_reported():
    verdicts = parse_authentication_results([
        'mx.receiver.example; spf=pass reason="ok" reason="again"; '
        "dmarc=fail header.from="
    ])
    assert verdicts.spf is None and verdicts.dmarc is None
    assert verdicts.warnings == ("Ignored malformed Authentication-Results clause.",)
