# Changelog

## Unreleased

### Hardened

- Bound `.eml` input to 25 MiB by default, with configurable file limits,
  nonblocking rejection of special files, and MIME depth/part limits.
- Preserve recoverable text with warnings for unknown charsets, invalid base64,
  and malformed multipart content.
- Parse authentication methods only from complete topmost-header clauses;
  ignore comments and quoted values, and surface ambiguous or malformed claims.
- Mark authentication results as recorded and unverified in text/JSON output.
- Recognize filename-bearing inline attachments and keep encapsulated emails
  and attached multipart containers out of outer-body analysis.
- Disclose when attachment hashes describe serialized MIME rather than original
  bytes using the `hash_basis` field.
- Escape terminal controls and invisible format characters in report fields and
  errors; preserve original values in machine-readable JSON.

### Calibrated

- Check every Reply-To address: report addresses without a usable domain and
  Reply-To domains that imitate protected brands, so an ordinary first address
  cannot hide a later lookalike.
- Treat addresses without both a local part and a domain as having no domain.
- For Constant Contact mail with recorded SPF/DKIM/DMARC passes, no warnings
  and no other medium or high finding: report an ordinary differing Reply-To
  as low instead of medium, and anchor text routed through the exact documented
  `rs6.net/tn.jsp` click-tracking route as a low "destination unverified"
  warning instead of a high mismatch. Malformed, IP, mixed-script and lookalike
  reply targets, and brand, lookalike, mixed-script or login-style link text,
  keep their normal severity.

### Validation

- Expand the regression suite to 349 synthetic tests.
- Add CI for Linux Python 3.11–3.14 and macOS/Windows Python 3.14.
- Build and smoke-test wheel/source archives using isolated installations
  outside the checkout without network access during installation.

No tagged release or PyPI package has been published. Licensing and formal
release remain pending final review.
