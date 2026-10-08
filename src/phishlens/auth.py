"""Read reported SPF, DKIM and DMARC verdicts from the topmost header.

Header position alone does not establish who added a header. These are recorded
claims, not verified authentication: PhishLens does not check signatures, DNS,
or the receiving provider's trust boundary. Lower headers are not combined with
the selected header.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_KEYWORD = r"[a-z0-9][a-z0-9-]*"
_QUOTED = r'"(?:[^"\\]|\\.)*"'
# RFC 8601 uses the MIME token / quoted-string definition for authserv-id and
# reason. Semicolons in quoted values must remain part of those values.
_TOKEN = r"[!#$%&'*+.^_`{|}~a-zA-Z0-9-]+"
_VALUE = rf"(?:{_QUOTED}|{_TOKEN})"
_AUTHSERV_RE = re.compile(rf"[ \t]*({_VALUE})(?:[ \t]+[0-9]+)?[ \t]*")
_METHOD_RE = re.compile(
    rf"[ \t]*({_KEYWORD})(?:[ \t]*/[ \t]*[0-9]+)?[ \t]*=[ \t]*"
    rf"({_KEYWORD})(?=[ \t]|$)", re.IGNORECASE | re.ASCII,
)
_KNOWN_METHOD_RE = re.compile(r"[ \t]*(spf|dkim|dmarc)(?=[ \t/=]|$)", re.IGNORECASE | re.ASCII)
# Properties can contain email identities, including quoted local-parts. Their
# contents are not used as verdicts, and their syntax is only checked enough to
# delimit complete supporting values safely.
_P_VALUE = rf'(?:{_QUOTED}(?:@[^\s"();\\]+)?|[^\s"();\\]+)'
_DETAIL_RE = re.compile(
    rf"[ \t]+(?:(?P<reason>reason)[ \t]*=[ \t]*{_VALUE}|"
    rf"{_KEYWORD}[ \t]*\.[ \t]*{_KEYWORD}[ \t]*=[ \t]*{_P_VALUE})"
    rf"(?=[ \t]|$)", re.IGNORECASE | re.ASCII,
)
_METHODS = ("spf", "dkim", "dmarc")


@dataclass(frozen=True)
class AuthVerdicts:
    spf: str | None
    dkim: str | None
    dmarc: str | None
    authserv_id: str | None
    warnings: tuple[str, ...] = ()

    def summary(self) -> str:
        parts = [f"{name.upper()} {value or 'unknown'}" for name, value in
                 (("spf", self.spf), ("dkim", self.dkim), ("dmarc", self.dmarc))]
        return " · ".join(parts)


def _split_clauses(raw: str) -> list[str] | None:
    """Remove nested RFC comments and split only unquoted semicolons.

    The iterative scanner also respects quoted-pairs inside comments and
    quoted strings. Unbalanced delimiters make the whole header ambiguous.
    """
    raw = re.sub(r"\r?\n[ \t]+", " ", raw)
    clauses: list[str] = []
    current: list[str] = []
    comment_depth = 0
    quoted = False
    escaped = False
    for char in raw:
        if (ord(char) < 32 and char != "\t") or ord(char) == 127:
            return None
        if escaped:
            if quoted:
                current.append(char)
            escaped = False
        elif char == "\\":
            if not (comment_depth or quoted):
                return None
            if quoted:
                current.append(char)
            escaped = True
        elif comment_depth:
            if char == "(":
                comment_depth += 1
            elif char == ")":
                comment_depth -= 1
        elif quoted:
            current.append(char)
            if char == '"':
                quoted = False
        elif char == "(":
            current.append(" ")
            comment_depth = 1
        elif char == ")":
            return None
        elif char == '"':
            current.append(char)
            quoted = True
        elif char == ";":
            clauses.append("".join(current))
            current = []
        else:
            current.append(char)
    if comment_depth or quoted or escaped:
        return None
    clauses.append("".join(current))
    return clauses


def _valid_details(clause: str, position: int) -> bool:
    """Require reason / property values after a method, not a second method."""
    saw_detail = False
    while position < len(clause):
        match = _DETAIL_RE.match(clause, position)
        if match is None:
            return not clause[position:].strip(" \t")
        if match.group("reason") and saw_detail:
            return False
        saw_detail = True
        position = match.end()
    return True


def parse_authentication_results(headers: list[str]) -> AuthVerdicts | None:
    if not headers:
        return None
    clauses = _split_clauses(headers[0])
    if clauses is None or len(clauses) < 2:
        return AuthVerdicts(None, None, None, None, (
            "Malformed topmost Authentication-Results header; verdicts are unknown.",
        ))
    service = _AUTHSERV_RE.fullmatch(clauses[0])
    if service is None:
        return AuthVerdicts(None, None, None, None, (
            "Invalid authserv-id in the topmost Authentication-Results header; verdicts are unknown.",
        ))
    authserv_id = service.group(1)
    if authserv_id.startswith('"'):
        authserv_id = re.sub(r"\\(.)", r"\1", authserv_id[1:-1])
    if len(clauses) == 2 and clauses[1].strip().lower() == "none":
        return AuthVerdicts(None, None, None, authserv_id)
    if any(clause.strip().lower() == "none" for clause in clauses[1:]):
        return AuthVerdicts(None, None, None, authserv_id, (
            "Malformed Authentication-Results header mixes 'none' with method results; verdicts are unknown.",
        ))

    found: dict[str, set[str]] = {}
    malformed_methods: set[str] = set()
    warnings: list[str] = []
    for clause in clauses[1:]:
        match = _METHOD_RE.match(clause)
        if match is None or not _valid_details(clause, match.end()):
            # A malformed duplicate cannot silently leave an earlier 'pass'
            # as the only reported claim for the same method.
            known_method = _KNOWN_METHOD_RE.match(clause)
            if known_method:
                malformed_methods.add(known_method.group(1).lower())
            warning = "Ignored malformed Authentication-Results clause."
            if warning not in warnings:
                warnings.append(warning)
            continue
        method, result = (part.lower() for part in match.groups())
        if method in _METHODS:
            found.setdefault(method, set()).add(result)

    verdicts: dict[str, str | None] = {}
    for method in _METHODS:
        results = found.get(method, set())
        verdicts[method] = (
            next(iter(results)) if len(results) == 1 and method not in malformed_methods else None
        )
        if len(results) > 1:
            warnings.append(
                f"Conflicting {method.upper()} results in the topmost Authentication-Results header; verdict is unknown."
            )
    return AuthVerdicts(*(verdicts[method] for method in _METHODS), authserv_id, tuple(warnings))
