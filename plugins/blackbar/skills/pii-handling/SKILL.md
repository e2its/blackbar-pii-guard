---
name: pii-handling
description: >-
  Guidance for detecting and redacting personally identifiable information (PII)
  with Microsoft Presidio. Use whenever the user asks to find, scrub, mask,
  anonymize, or pseudonymize sensitive data (names, emails, phone numbers,
  credit cards, SSNs, IPs, etc.) in text, files, logs, or datasets, or when
  about to share content that may contain personal data externally.
---

# Handling PII with Presidio

This plugin wraps Microsoft Presidio. Two tools are available from the
`blackbar` MCP server:

- `presidio_analyze(text, language?, entities?)` — detects PII and returns each
  entity's type, span, score, and matched text.
- `presidio_anonymize(text, operator?, language?, entities?, key?)` — returns a
  transformed copy. Operators: `replace` (default, `<EMAIL_ADDRESS>`), `redact`
  (delete), `mask` (`****1234`), `hash`, and `encrypt` (reversible with a key).

## When to use which

- "Is there any personal data in this?" → `presidio_analyze`, then summarize.
- "Clean this up before I share it" → `presidio_anonymize` with `replace` or
  `mask`.
- "I need to re-identify later" → `presidio_anonymize` with `encrypt` and a key
  the user controls.
- Bulk files / datasets → read the content, analyze in chunks, then anonymize.

## Behavioral rules

- Never paste detected PII values back into chat, files, logs, or network calls
  beyond what's strictly necessary to answer.
- Tool results in this session may already be scrubbed by the PostToolUse hook;
  placeholders such as `<PERSON>` or `<EMAIL_ADDRESS>` are intentional — do not
  try to recover the originals.
- Presidio is high-recall but not perfect. For compliance-critical work, tell
  the user that a human should review the output.
- If a tool reports the analyzer is unavailable, point the user to the plugin
  README to start the Presidio service or install the library.

## Default entity coverage

PERSON, EMAIL_ADDRESS, PHONE_NUMBER, CREDIT_CARD, US_SSN, IBAN_CODE, IP_ADDRESS,
LOCATION, DATE_TIME, URL, US_BANK_NUMBER, US_DRIVER_LICENSE, US_PASSPORT,
CRYPTO, MEDICAL_LICENSE, and more. Restrict scope by passing `entities`.
