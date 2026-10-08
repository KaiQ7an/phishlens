# PhishLens

An offline command-line tool that explains why an email might be phishing.
Give it an exported `.eml` file and it reports sender inconsistencies, misleading
links, risky attachment types, and social-engineering language. Every finding
includes a reason, evidence when available, and its contribution to the score.

The current MVP uses Python's standard library, with no runtime dependencies or
API keys. It includes English and Chinese rules and six synthetic sample emails.

## Quick start

Requires Python 3.11 or newer. Development has been checked on Python 3.14.8.
From the project directory, run:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install '.[dev]'

phishlens analyze tests/fixtures/clean_newsletter.eml
phishlens analyze tests/fixtures/zh_fake_police.eml
python -m pytest -q
```

Installing the development dependencies needs access to a Python package index.
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
```

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
| 1 | The input could not be read, was empty, or exceeded supported input limits |
| 2 | The risk threshold was reached, or command-line arguments were invalid |

JSON reports contain the source path, subject, sender, recorded authentication
results, score, risk level, findings, extracted links, and attachment metadata
including full SHA-256 hashes. The `parsing_warnings` array is empty for messages
with no detected parsing issues.

If a charset is unknown or text bytes are damaged, PhishLens preserves as much
text as it can and includes a warning in both text and JSON reports. Invalid
base64 and malformed or truncated multipart content also produce warnings.
Warnings do not add risk points or change exit status: they mean analysis may be
incomplete, so a low score deserves extra caution.

## Example

The synthetic Chinese fake-police email passes all three recorded authentication
checks, yet its language produces a high-risk verdict. Output excerpt:

```text
PhishLens report: tests/fixtures/zh_fake_police.eml
  Subject : 【紧急通知】您的护照涉嫌一宗洗钱案件
  From    : 中国驻墨尔本总领事馆 <notice@cn-consulate-service.example>
  Auth    : SPF pass · DKIM pass · DMARC pass  (by mx.receiver.example)

  Verdict : HIGH RISK  (score 80/100)

Findings
  [HIGH   +30] Claims to be police or government but was not sent from a government domain
               evidence: '公安', '警官', '涉嫌', '洗钱', '通缉'; sender cn-consulate-service.example
  [HIGH   +30] Tells you to keep it secret or cut off contact
               evidence: '保密', '切勿告知'
  [MEDIUM +15] Asks for money or an unusual payment method
               evidence: '保证金', '安全账户'
  [LOW    + 5] Creates time pressure
               evidence: '紧急', '24小时内'
```

The clean newsletter scores 0/100. All five phishing fixtures receive high-risk
verdicts. These are hand-written demonstrations, not a measurement of detection
accuracy on real email.

## What it checks

- The topmost `Authentication-Results` header for recorded SPF, DKIM and DMARC
  verdicts; missing authentication information is also reported.
- Sender display names, lookalike sender domains, differing Reply-To domains,
  and Return-Path differences.
- HTML and plain-text links: misleading anchor text, lookalike domains,
  punycode, mixed scripts, bare IP addresses, URL shorteners, user-info tricks,
  insecure login-style URLs, and form destinations.
- Attachment filenames and extensions: executables, double extensions, macro
  documents, HTML/SVG files, disk images, and archives.
- English and Chinese language suggesting urgency, authority, secrecy, or
  unusual payments. Keywords inside URLs are excluded from this check.

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

## Safety model and limitations

- Analysis reads only the file you provide. There is no inbox connection,
  telemetry, DNS lookup, URL fetch, or reputation-service request.
- HTML is parsed as text; it is not rendered in a browser and scripts are not
  executed. Links and form destinations are extracted without being visited.
- Attachment payloads are MIME-decoded in memory to calculate their size and
  SHA-256 hash. They are not saved, launched, unpacked, or scanned for malware.
  Attachment warnings are based on filenames, not verified file contents.
- Authentication results are read from the first header, not independently
  verified. The tool cannot prove that this header came from a trusted receiving
  server. Arbitrary or edited `.eml` files can contain forged results.
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

The current suite has 91 tests for message parsing, input limits, malformed MIME,
text decoding, authentication headers, domains, links, attachment rules, language
signals, scoring, and CLI output.
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
- **Next:** a stronger policy for identifying trusted authentication headers
  and further malformed-message coverage.
- **Later:** broader domain data and configurable brand/language rules, plus
  batch analysis and report comparison.
- **Optional future work:** explicit opt-in reputation lookups with caching and
  clear disclosure of submitted URLs/hashes. `intel.py` currently contains an
  interface stub only; external lookups are not implemented.

## Author

KaiQian Xue
