# Changelog

## Unreleased

### Hardened

- Bound `.eml` input to 25 MiB by default, with configurable file limits,
  nonblocking rejection of special files, and MIME depth/part limits.
- Preserve recoverable text with warnings for unknown charsets, invalid base64,
  and malformed multipart content.
- Surface parsing defects and repeated From/Reply-To headers while retaining
  the first identity header's recovered addresses.
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
- Keep malformed visible URLs, nonstandard ports and percent-encoded link text
  outside route calibration. Forms or other medium/high URL findings disable
  routing reductions for the whole message, regardless of link order.

### Detection

- Read the sender display name together with the subject and body for content
  signals, so authority claims made only in the name are caught. Add customs
  (海关) to authority phrases and "do not call the police" (不要报警) to
  secrecy phrases.
- Treat bank-detail changes and parcel/customs fees as payment requests. Add
  medium signals for money wanted before any meeting or inspection and for
  requests to scan a QR code.
- Treat SharePoint, OneDrive, Office 365, Microsoft 365 and Australia Post as
  their brands in display names and domain tokens; add `sharepointonline.com`
  to Microsoft's sending domains.
- Flag archives whose password is given in the message text as high risk, and
  raise attached HTML/SVG pages from medium to high.
- Treat tax offices (taxation office, HMRC, 税务局) as authorities. Add medium
  signals for guaranteed investment returns and for threats to disable or
  delete an account or page; count USDT and crypto wallets as payment methods.
- Rate macro-enabled Office attachments as high, since Office blocks macros in
  files from the internet by default.
- Protect Facebook and Instagram, with "Meta" checked in display names only,
  and DocuSign.
- Add signals for job and commission offers, a relative's "new number", vague
  favours, prizes, wallet recovery phrases (high), gift card codes (high) and
  callback phishing: a charge paired with a phone number to dispute it (high).
- Recognise intents rather than single phrases: a payment verb followed by an
  amount, money sent to "my" account, deposits and fees, moving to a chat app,
  screen-sharing or remote-access requests, "wrong person" openers, parcel
  context, percentage investment returns, absent landlords and threats to
  delete a service. Deadlines such as "within 7 days" count as time pressure.

### Fixed

- Stop escalating every police or government mention from a non-government
  sender: the high finding now needs the claim in the sender name or subject,
  or alongside a request for money, identity details or secrecy. A university
  safety notice that tells students to contact the police is no longer flagged.
- Report evidence matched by both a phrase and a pattern once.

### Validation

- Add 172 labelled synthetic scenarios: a dev split for tuning and five
  holdout splits, each written after a round of rule changes and run once.
  `scripts/evaluate.py` reports precision and recall per split and, for newer
  holdouts, detection of reworded versus new categories. First-run recall on
  unseen holdouts ranged from 10% to 42% with no false alarms; the README
  explains what the rounds show. Remaining misses run as strict expected
  failures.
- Expand the regression suite to 620 synthetic tests.
- Add CI for Linux Python 3.11–3.14 and macOS/Windows Python 3.14.
- Build and smoke-test wheel/source archives using isolated installations
  outside the checkout without network access during installation.

No tagged release or PyPI package has been published. Licensing and formal
release remain pending final review.
