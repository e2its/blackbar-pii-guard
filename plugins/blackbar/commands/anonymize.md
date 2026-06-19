---
description: Anonymize PII in text using Microsoft Presidio (replace, mask, hash, redact, encrypt)
argument-hint: "[text] [--operator replace|mask|hash|redact|encrypt]"
---

Use the `presidio_anonymize` tool from the blackbar MCP server to produce
a privacy-safe version of the text.

Input: $ARGUMENTS

Steps:
1. Determine the text to anonymize (the argument, a referenced file's contents,
   or the current selection).
2. Pick the operator from the argument if given, otherwise default to `replace`.
   For `encrypt`, ask the user for a key first if they haven't supplied one.
3. Call `presidio_anonymize` with the text and operator.
4. Return the anonymized text in a copyable code block, and list which entity
   types were transformed.

Never store, log, or repeat the original PII values once anonymized.
