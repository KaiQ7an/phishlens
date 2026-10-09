# PhishLens

An offline command-line tool that explains why an email might be phishing.
Give it an exported `.eml` file and it reports sender inconsistencies, misleading
links, risky attachment types, and social-engineering language. Every finding
includes a reason, evidence when available, and its contribution to the score.

The current MVP uses Python's standard library, with no runtime dependencies or
API keys. It includes English and Chinese rules and six synthetic sample emails.

**Status:** active development. The code is public; a tagged Release or PyPI
package has not been published. Formal release is deferred until final review.

## Quick start

Requires Python 3.11 or newer. Development has been checked on Python 3.14.8.
On macOS or Linux, install the current source version:

```bash
git clone https://github.com/KaiQ7an/phishlens.git
cd phishlens
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .

phishlens analyze tests/fixtures/clean_newsletter.eml
phishlens analyze tests/fixtures/zh_fake_police.eml
```

If you already have the repository, start from its directory and skip cloning.
On Windows PowerShell, use the virtual environment's executables directly:

```powershell
git clone https://github.com/KaiQ7an/phishlens.git
cd phishlens
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install .
.\.venv\Scripts\phishlens.exe analyze .\tests\fixtures\clean_newsletter.eml
```

Cloning and installing build/development dependencies need network access.
Email analysis itself makes no network calls. The normal installation above
copies the package into the virtual environment; reinstall after editing source:

```bash
python -m pip install --force-reinstall --no-deps .
```

## Usage

Export an individual email as `.eml`, then pass its path to PhishLens:

```bash
phishlens analyze /path/to/message.eml
phishlens analyze /path/to/message.eml --json > report.json
phishlens analyze /path/to/message.eml --fail-on high
phishlens analyze /path/to/message.eml --max-size-mb 50
python -m phishlens analyze /path/to/message.eml
phishlens analyze /path/to/folder/                # every .eml in the folder
phishlens analyze one.eml two.eml --json > summary.json
```

Several paths, or a directory, give a summary table sorted by score, with each
file's verdict and top finding; directories are not searched recursively. Run
the command on a single file to see all findings and evidence. With `--json`,
the summary contains counts, every full report, and the files that could not
be analysed.

Export the complete original message as `.eml`, including its headers and MIME
body. A screenshot or copied body text cannot preserve authentication headers,
actual link destinations, or attachments for analysis. Keep personal messages
and reports outside the repository; for example, on macOS:

```bash
cd ~/Desktop/Projects/phishlens
source .venv/bin/activate
phishlens analyze "$HOME/Downloads/message.eml"
phishlens analyze "$HOME/Downloads/message.eml" --json > "$HOME/Downloads/phishlens-report.json"
```

Replace the example path with your exported file. A successful normal analysis
prints its verdict and the evidence, even when the verdict is high risk.

`--fail-on suspicious` fails for suspicious and high-risk verdicts;
`--fail-on high` fails only for high-risk verdicts. Without `--fail-on`, a
successful analysis exits with status 0 regardless of its verdict.

The default file limit is **25 MiB** (26,214,400 bytes). Use `--max-size-mb`
with a positive whole number to change it; one unit is 1,048,576 bytes. The tool
accepts regular files, including symlinks to regular files, and rejects empty
messages, pipes, and device files. It also rejects MIME trees with more than
1,000 parts (including the root) or a nesting depth above 30.

| Exit status | Meaning |
| --- | --- |
| 0 | Analysis completed below the requested threshold, or no threshold was set |
| 1 | An input could not be read, was empty, or exceeded supported input limits, or a directory had no `.eml` files |
| 2 | The risk threshold was reached by any analysed file, or command-line arguments were invalid |

In a batch, status 1 takes precedence over status 2: an incomplete run is
reported as incomplete even if another file reached the threshold.

JSON reports contain the source path, subject, sender, recorded authentication
results, score, risk level, findings, extracted links, and attachment metadata
including full SHA-256 hashes. The `parsing_warnings` array is empty for messages
with no detected parsing issues.

Authentication objects include `verified: false` and a `warnings` array. The
verdicts are claims recorded in the email, not independently validated results.
Conflicting duplicate results or malformed clauses can make a method's result
`null` (shown as unknown in text reports). Lower authentication headers are not
merged with the selected header.

Attachment objects include `hash_basis`: `decoded-payload` for ordinary files,
or `serialized-mime` for multipart containers and forwarded emails. The latter
hash describes the parser's in-memory MIME representation, not the original
attachment bytes, and comes with an explicit warning.

If a charset is unknown or text bytes are damaged, PhishLens preserves as much
text as it can and includes a warning in both text and JSON reports. Invalid
base64 and malformed or truncated multipart content also produce warnings.
Defective or repeated From and Reply-To headers produce warnings while keeping
the first header's recovered addresses available for analysis.
Warnings do not add risk points or change exit status: they mean analysis may be
incomplete, so a low score deserves extra caution.

## Example

The synthetic Chinese fake-police email passes all three recorded authentication
checks, yet its language produces a high-risk verdict. Output excerpt:

```text
PhishLens report: tests/fixtures/zh_fake_police.eml
  Subject : 【紧急通知】您的护照涉嫌一宗洗钱案件
  From    : 中国驻墨尔本总领事馆 <notice@cn-consulate-service.example>
  Auth    : SPF pass · DKIM pass · DMARC pass  (by mx.receiver.example)  (recorded, unverified)

  Verdict : HIGH RISK  (score 80/100)

Findings
  [HIGH   +30] Claims to be police, a tax office or government but was not sent from a government domain
               evidence: '公安', '警官', '领事馆', '涉嫌', '洗钱'; sender cn-consulate-service.example
  [HIGH   +30] Tells you to keep it secret or cut off contact
               evidence: '保密', '切勿告知'
  [MEDIUM +15] Asks for money or an unusual payment method
               evidence: '保证金', '安全账户', '缴纳'
  [LOW    + 5] Creates time pressure
               evidence: '紧急', '24小时内'
```

The clean newsletter scores 0/100. All five phishing fixtures receive high-risk
verdicts. These are hand-written demonstrations, not a measurement of detection
accuracy on real email.

## What it checks

- The topmost `Authentication-Results` header for recorded SPF, DKIM and DMARC
  verdicts; comments and quoted supporting values are not treated as results.
  Missing, malformed, or conflicting authentication information is reported.
- Sender display names, lookalike sender domains, Return-Path differences, and
  every Reply-To address: differing domains, addresses without a usable domain,
  and Reply-To domains that imitate a protected brand.
- HTML and plain-text links: misleading anchor text, lookalike domains,
  punycode, mixed scripts, bare IP addresses, URL shorteners, user-info tricks,
  insecure login-style URLs, and form destinations.
- Attachment filenames and extensions: executables, double extensions, macro
  documents and HTML/SVG files (high risk), disk images, and archives, including named inline
  MIME parts. An archive whose password is given in the message text is flagged
  as high risk; the archive itself is never opened.
- English and Chinese language that signals a scam's intent: urgency and
  deadlines, claims of authority (police, embassies, tax offices), secrecy or
  isolation, requests for money (including a payment verb followed by an
  amount, deposits and fees), identity documents, passwords or wallet recovery
  phrases, guaranteed or percentage investment returns, prizes, job and
  commission offers, a relative's "new number", vague favours, moving the
  conversation to a chat app, screen-sharing or remote-access requests,
  account takedown threats, money wanted before any meeting or inspection,
  requests to scan a QR code, gift card codes, and a charge paired with a phone
  number to dispute it (callback phishing). The sender's display name is read
  with the subject and body; keywords inside URLs are excluded. An authority
  mentioned in passing ("contact Victoria Police") is not escalated unless the
  sender name or subject claims it, or the message also asks for something.
- Product names such as SharePoint, OneDrive and Australia Post count as their
  brands in display names and domains. Protected brands include Monash,
  Microsoft, Google, Apple, PayPal, CommBank, Australia Post, myGov, Facebook
  (Meta), Instagram and DocuSign.

## Scoring

| Finding severity | Points |
| --- | ---: |
| Info | 0 |
| Low | 5 |
| Medium | 15 |
| High | 30 |

Points are added and capped at 100. Scores of 0–19 are **low risk**, 20–49 are
**suspicious**, and 50–100 are **high risk**. The score is a rule-based indicator,
not a probability. Passing authentication does not subtract risk points.

One narrow calibration applies to a single bulk-mail pattern. It is used only
when the From domain is Constant Contact's documented shared sending domain
(`ccsend.com`), the topmost header records SPF, DKIM and DMARC all as `pass`
with no authentication or parsing warnings, and the email has no other medium
or high content, attachment, header or URL finding. Then:

- A Reply-To on a different, ordinary domain is reported as **low** instead of
  medium, because the service rewrites From addresses. Malformed, IP-address,
  mixed-script or lookalike reply targets keep their normal severity, and every
  reply address is still checked.
- An HTML link whose text names another site but which goes through the
  service's documented click-tracking route (`https://*.rs6.net/tn.jsp?f=…`,
  matched exactly) is reported as a **low** "final destination is unverified"
  warning instead of a high anchor mismatch. Link text naming a protected brand,
  a lookalike, a mixed-script domain or a login page keeps the high mismatch,
  as does malformed URL text. Only plain ASCII site names and HTTP(S) URLs with
  standard ports qualify; percent-encoded text is outside this narrow pattern.
  A form or another medium/high URL finding disables both reductions for the
  entire email, regardless of link order.

This is routing context only. It does not verify the sender, the tracking token
or the final destination, and it never removes authentication failures or any
other finding.

The service documents [From rewriting and Reply-To preservation](https://knowledgebase.constantcontact.com/email-digital-marketing/articles/KnowledgeBase/51400-How-your-From-email-address-may-be-impacted-by-the-latest-email-authentication-requirements%3Flang%3Den_US),
[shared sender subdomains](https://knowledgebase.constantcontact.com/email-digital-marketing/articles/KnowledgeBase/53013-Customize-the-subdomain-for-your-From-email-address?lang=en_US),
and [its web domains](https://knowledgebase.constantcontact.com/email-digital-marketing/articles/KnowledgeBase/5800-Safelist-Constant-Contact-web-domains-in-a-security-program?lang=en_US).
Its support community also describes [intermediate click-tracking links](https://community.constantcontact.com/t5/Product-Ideas/Turn-off-link-tracking-in-campaigns/idi-p/334097).

## Evaluation

`scripts/evaluate.py` scores 172 labelled synthetic scenarios in
`tests/scenarios.py` (`--markdown` or `--json` for other formats). Each
scenario's label was written before the rules were run against it. The
**dev** split is used to find and fix rule gaps. Each **holdout** split was
written after a round of rule changes, run once, and never used for tuning.
Its missed categories then shaped the next round's dev scenarios, with fresh
wording, so only the newest holdout measures unseen messages. A phishing
scenario counts as detected when it scores suspicious or high.

| Split | Written after | Phishing detected on first run | Phishing detected now | False alarms |
| --- | --- | ---: | ---: | ---: |
| holdout | the original rules | 1 / 6 | 6 / 6 | 0 / 6 |
| holdout2 | round 2 | 3 / 8 | 6 / 8 | 0 / 6 |
| holdout3 | round 3 | 1 / 10 | 5 / 10 | 0 / 8 |
| holdout4 | round 4 | 3 / 10 | 8 / 10 | 0 / 8 |
| holdout5 | round 5 | 5 / 12 | (current unseen set) | 0 / 10 |

The dev split has 88 scenarios with 98% recall and one false alarm.
Holdout4 and holdout5 separate reworded versions of categories earlier
rounds covered (`variant-`) from categories no round targeted (`new-`):

| Split | Reworded known category | New category |
| --- | ---: | ---: |
| holdout4 (phrase rules) | 1 / 6 | 2 / 4 |
| holdout5 (intent rules) | 4 / 7 | 1 / 5 |

What the rounds show:

- First-run recall on unseen scenarios stayed between 10% and 42%. Rules
  mostly catch what they were written from; the much higher "now" column is
  the effect of tuning, not of generalisation.
- Rounds one to four added phrases per category. Holdout4 showed these barely
  carried over even to reworded scams of the same category (1 of 6).
- Round five instead targeted intents (a payment verb with an amount, moving
  to a chat app, remote access, secrecy), each written against two independent
  wordings. Holdout5's reworded scams were caught 4 of 7 times, though two of
  those were caught by older brand rules, so the sample is too small to claim
  more than a possible improvement.
- Scams in new categories are still mostly missed, and some lures cannot be
  separated from genuine mail by offline text at all: a "log in to view your
  letter" notice linking to the sender's own login page reads like a real HR
  portal notice without sender reputation.
- No holdout false alarms were recorded across 38 legitimate scenarios,
  including deliberate probes (real fines, bonds, refunds, remote IT support,
  chat-group invitations, police advice from a university).
- Synthetic attacker domains are stylised (hyphenated `.example` names), so
  rules based on domain shape were deliberately not added; they would exploit
  an artefact of the test data rather than a property of real phishing.

Known misses and the one dev false alarm, a newsletter whose tracked link
shows the final URL as its text, are listed in `KNOWN_GAPS` and run as strict
expected failures, so a fix or regression is reported by the test suite.
These are small synthetic sets, not measurements on real mail.

## Safety model and limitations

- Analysis reads only the file you provide. There is no inbox connection,
  telemetry, DNS lookup, URL fetch, or reputation-service request.
- HTML is parsed as text; it is not rendered in a browser and scripts are not
  executed. Links and form destinations are extracted without being visited.
- Attachment payloads are MIME-decoded in memory to calculate their size and
  SHA-256 hash. They are not saved, launched, unpacked, or scanned for malware.
  Attachment warnings are based on filenames, not verified file contents.
  Forwarded emails and attached multipart containers are treated as opaque
  attachments: their inner text, links, and files are not scored as part of the
  outer email. Container size/hash uses a serialized representation with
  explicit provenance rather than claiming the original bytes are available.
- Authentication results are read from the first header, not independently
  verified. The tool cannot prove that this header came from a trusted receiving
  server. Arbitrary or edited `.eml` files can contain forged results.
- Text reports escape control and invisible formatting characters in email
  fields, so they cannot clear the terminal or insert fake report lines. JSON
  reports escape these characters while retaining the original parsed values.
- Domain and language rules are intentionally small. The built-in suffix list
  is not the complete Public Suffix List, and brand/confusable lists are not
  exhaustive. Legitimate messages can trigger warnings; phishing can be missed.
- Low risk means few recognized signals, not proof that an email is safe.
  Government-looking domains and authentication passes do not establish the
  legitimacy of the sender's claims.
- Input size is checked before parsing, with a bounded read to handle files that
  grow during reading. MIME part/depth limits are checked after the standard
  library parser builds the message. Parsing and decoding still use memory, and
  these checks are not a hard memory or runtime sandbox. This tool is intended
  for local inspection, not an exposed service accepting arbitrary uploads.
- Reports can include sensitive subjects, addresses, URLs, and filenames.
  Keep real emails and generated reports out of public repositories.

## Development

```bash
source .venv/bin/activate
python -m pip install '.[dev]'
python -m pytest -q
```

The current suite has 625 tests (including 18 expected failures for known
gaps) for message parsing, input limits, malformed MIME,
text decoding, authentication-header ambiguity, domains, links, inline/container
attachments, language signals, scoring, mailing-route boundaries, safe report
rendering, CLI output, and the labelled evaluation scenarios.
Fixtures use synthetic messages and reserved example domains, with no real inbox
data. The fixture generator is `tests/fixtures/build_fixtures.py`.

The code follows this flow:

```text
.eml → message.py → auth / domains / urls / content / attachments
                 → analyzer.py + scoring.py → report.py → cli.py
```

For a contribution, add a synthetic regression case for a meaningful behavior
change, reinstall the package, and run the suite. Keep analysis offline and
avoid adding real messages, credentials, or generated reports.

### CI and package validation

GitHub Actions runs the suite on Linux with Python 3.11–3.14 and on macOS/Windows
with Python 3.14. It builds a wheel and source distribution, then installs each
into a fresh virtual environment outside the checkout. All six sample emails
are read from the source archive for CLI smoke checks, so missing package files
or fixtures cannot be masked by the source directory.

To run the package check locally:

```bash
python -m pip install build twine
python -m build
python -m twine check dist/*
python -m pip download --only-binary=:all: --dest /tmp/phishlens-build-deps 'setuptools>=68' wheel
python scripts/verify_distribution.py --build-deps /tmp/phishlens-build-deps
```

The verification installs use predownloaded build wheels and `--no-index`.
CI retains ordinary build artifacts for inspection and does not publish a
GitHub Release or upload to PyPI. See [CHANGELOG.md](CHANGELOG.md) for unreleased
changes.
See [HANDOFF.md](HANDOFF.md) for maintainer context and the next work session.

### macOS editable-install troubleshooting

An editable installation can fail with `No module named 'phishlens'` if its
`.pth` file has the macOS hidden flag. Python skips that file even when its path
is correct. On this development machine, removing the flag did not persist.
Use the ordinary installation documented above to avoid depending on `.pth`
processing:

```bash
python -m pip install --force-reinstall --no-deps .
phishlens --version
```

## Roadmap

- **Current MVP:** offline `.eml` analysis, explained text/JSON reports, English
  and Chinese rules, synthetic regression fixtures, bounded file input, MIME
  structure limits, and visible parsing warnings.
- **Current hardening:** conservative authentication parsing with explicit
  unverified provenance, inline/container attachment handling, escaped report
  controls, and cross-platform CI/package verification.
- **Before formal release:** review CI results, expand independent synthetic
  scenarios and compatibility checks, decide licensing, and complete final
  usability review. Tagged releases and PyPI publication remain deferred.
- **Later:** broader domain data and configurable brand/language rules, plus
  report comparison. Batch analysis of several files or a directory is
  available now.
- **Optional future work:** explicit opt-in reputation lookups with caching and
  clear disclosure of submitted URLs/hashes. `intel.py` currently contains an
  interface stub only; external lookups are not implemented.

## Author

KaiQian Xue
