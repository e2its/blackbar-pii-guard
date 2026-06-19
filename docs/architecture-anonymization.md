# blackbar — reversible anonymization architecture

Goal: keep **unencrypted PII out of the model and off the network**, while still
being able to **restore the original values locally** with a key.

The hard constraint that shapes everything: on a **Claude Pro/Max subscription**
the conversation transport cannot be intercepted (using the subscription OAuth
token through a proxy violates Anthropic's Terms and is blocked server-side as of
2026). And Claude Code hooks **cannot rewrite the user's prompt nor the model's
output** — only tool inputs (`PreToolUse.updatedInput`) and tool results
(`PostToolUse.updatedToolOutput`).

Therefore a fully *transparent* round-trip is only possible with a **Console API
key** (path 3). For subscription, the achievable goal is **maximum coverage with
minimum friction**, not invisibility.

## The reversible token (already implemented)

`bb_crypto` (Python) and the equivalent in `desktop/server/index.js` (Node)
produce self-describing tokens:

```
<ENC:ENTITY_TYPE:base64url(MAGIC|salt|nonce|ciphertext|tag)>
```

Self-contained (no external span store), authenticated (wrong key / tamper →
left intact), and interchangeable between the Python and Node implementations.
Every path below reuses this single token format.

## Paths

### Path 1 — Claude Code hooks (subscription, automatic for tool data)
Local, ToS-clean (hooks run on your machine, never touch the OAuth token).

- `PostToolUse` → **encrypt** mode: PII in tool results (Read/Bash/WebFetch/…)
  becomes `<ENC:…>` before the model sees it. *(today it does one-way replace)*
- `PreToolUse` → use `updatedInput` to **encrypt PII in outbound tool calls**
  (WebFetch/WebSearch/Bash) so it never leaves the machine in clear.
- `UserPromptSubmit` → can only **warn or block** PII in the typed prompt
  (cannot encrypt it — platform limit).
- Decryption of the model's answer is a **manual command** (`/blackbar:decrypt`)
  because no hook can rewrite assistant output.
- Needs a **persistent local session key** shared by the hooks.

Covers the biggest PII ingress in coding workflows (files, commands, web)
automatically. Does **not** cover what the user types.

### Path 2 — Local enc/dec utility (subscription, ALL interfaces) ★ universal
A standalone local tool that transforms text before it enters / after it leaves
*any* app. Interface-agnostic, so it is the single answer for **Claude Desktop,
the Claude Chrome extension, Office add-ins, claude.ai web, and Claude Code**.

- **CLI**: `blackbar enc|dec|scan|keygen` (reuses `bb_crypto` + `presidio_client`).
  stdout carries only the transformed text (pipe/clipboard-friendly).
- **Clipboard integration**: OS hotkey → `enc` the selection before paste,
  `dec` the copied answer. (xclip/wl-clipboard on Linux, pbcopy/pbpaste on
  macOS, clip/PowerShell on Windows.)
- ToS-clean: never touches the OAuth token, never proxies traffic.

Friction: it is a hotkey/command, not invisible. But it is universal.

### Path 3 — Local streaming proxy (API key only, fully transparent) ✅ MVP
A local server implementing the Anthropic Messages API (`/v1/messages`) with
**SSE streaming**, pointed to by `ANTHROPIC_BASE_URL`. Encrypts every text block
on the way out, decrypts `<ENC:…>` on the way back — including tokens split
across stream chunks (held back and flushed on `content_block_stop`). Requires a
**Console API key** (subscription OAuth is prohibited). Works with Claude Code
only (Desktop cannot set a base URL).

Implemented in [`../proxy/blackbar_proxy.py`](../proxy/blackbar_proxy.py); see
[`../proxy/README.md`](../proxy/README.md). Core transforms (request encryption,
streaming split-token reassembly, non-streaming decrypt) are unit-tested; the
HTTP plumbing needs a live Console key to exercise end-to-end.

### Path 4 — Browser extension (optional, transparent on web)
A content script that encrypts the input box on submit and decrypts `<ENC:…>` in
the response DOM, entirely client-side (no proxy, no OAuth use). Closest to
invisible for the Chrome extension / claude.ai web. Grayer ToS area (alters the
page); deferred.

## Coverage vs transparency

| Surface | Path 1 hooks | Path 2 utility | Path 3 proxy | Path 4 ext |
| --- | --- | --- | --- | --- |
| Claude Code (CLI/VS Code) | auto (tools) | hotkey | transparent* | — |
| Claude Desktop | — | hotkey | — | — |
| Claude Chrome / web | — | hotkey | — | transparent |
| Office add-ins | — | hotkey | — | — |

\* transparent but requires a Console API key.

## Build order
1. **Path 2 CLI** (universal engine) — reuse `bb_crypto`/`presidio_client`.
2. **Path 2 clipboard wrappers** + **Path 1 reversible hooks** (in parallel).
3. **Path 3 streaming proxy** (after subscription paths validated).
4. **Path 4 browser extension** (optional).

## Honesty
- Presidio is high-recall, not perfect — "never" is a target, not a proof. Pair
  with `fail=closed` and a strict entity allow-list for sensitive work.
- Long opaque tokens may be altered by the model when echoed; decryption then
  fails safe (token left intact, no leak) but the value is lost. Deterministic
  per-value tokens or short pseudonyms improve echo-survival; tracked separately.
