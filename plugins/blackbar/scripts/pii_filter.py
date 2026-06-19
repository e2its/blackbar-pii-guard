#!/usr/bin/env python3
"""
pii_filter.py
=============
Single entry point for every blackbar hook. The lifecycle event name is
passed as the first CLI argument (see hooks/hooks.json); the event payload
arrives as JSON on stdin. We emit Claude Code hook-output JSON on stdout.

Per-event behaviour (all configurable via env vars):

  UserPromptSubmit  detect PII in the prompt. A hook CANNOT rewrite a prompt,
                    so we either warn (inject additionalContext) or block.
                    PRESIDIO_GUARD_PROMPT_POLICY = warn | block | off   (warn)

  PreToolUse        gate outbound network tools (WebFetch / WebSearch). PII in
                    a URL or query would leave the machine, so we ask or deny.
                    PRESIDIO_GUARD_EGRESS_POLICY = ask | block | warn | off (ask)

  PostToolUse       redact PII inside the tool RESULT before the model sees it,
                    via updatedToolOutput. The file/command output on disk is
                    untouched -- only what reaches the model is scrubbed.
                    PRESIDIO_GUARD_RESULT_REDACTION = on | off          (on)

  MessageDisplay    redact PII from the on-screen assistant text (display only).
                    PRESIDIO_GUARD_DISPLAY_REDACTION = on | off         (off)

If Presidio is unreachable we FAIL OPEN by default (work continues) but surface
a one-line systemMessage so you know redaction is inactive. Set
PRESIDIO_GUARD_FAIL = closed to block instead.
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from presidio_client import PresidioClient, PresidioUnavailable, Span  # noqa: E402

EGRESS_TOOLS = {"WebFetch", "WebSearch"}


def _env(name: str, default: str) -> str:
    v = os.environ.get(name)
    return v if v not in (None, "") else default


def _emit(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj))
    sys.stdout.flush()


def _summary(spans: list[Span]) -> str:
    types = sorted({s.entity_type for s in spans})
    return ", ".join(types)


def _fail(message: str) -> None:
    """Handle a Presidio outage according to the fail mode."""
    if _env("PRESIDIO_GUARD_FAIL", "open") == "closed":
        sys.stderr.write(f"[blackbar] blocked: {message}")
        sys.exit(2)
    _emit({"systemMessage": f"blackbar inactive: {message}"})
    sys.exit(0)


# --------------------------------------------------------------------------- #
# Event handlers
# --------------------------------------------------------------------------- #
def handle_user_prompt_submit(data: dict, client: PresidioClient) -> None:
    policy = _env("PRESIDIO_GUARD_PROMPT_POLICY", "warn")
    if policy == "off":
        sys.exit(0)
    spans = client.analyze(data.get("prompt", ""))
    if not spans:
        sys.exit(0)
    found = _summary(spans)
    if policy == "block":
        _emit(
            {
                "decision": "block",
                "reason": (
                    f"blackbar detected PII in your prompt ({found}). "
                    "Remove or redact it, then resubmit."
                ),
                "suppressOriginalPrompt": True,
            }
        )
        sys.exit(0)
    # warn: let it through but tell Claude what was present
    _emit(
        {
            "hookSpecificOutput": {
                "hookEventName": "UserPromptSubmit",
                "additionalContext": (
                    f"[blackbar] The user's prompt contains likely PII "
                    f"({found}). Treat these values as sensitive; do not repeat "
                    "them verbatim or write them to logs, files, or network calls."
                ),
            }
        }
    )
    sys.exit(0)


def handle_pre_tool_use(data: dict, client: PresidioClient) -> None:
    policy = _env("PRESIDIO_GUARD_EGRESS_POLICY", "ask")
    if policy == "off":
        sys.exit(0)
    tool = data.get("tool_name", "")
    if tool not in EGRESS_TOOLS:
        sys.exit(0)
    blob = json.dumps(data.get("tool_input", {}))
    spans = client.analyze(blob)
    if not spans:
        sys.exit(0)
    found = _summary(spans)
    reason = (
        f"blackbar: this {tool} request contains likely PII ({found}) "
        "that would leave your machine."
    )
    if policy == "warn":
        _emit(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "additionalContext": f"[blackbar] {reason}",
                }
            }
        )
        sys.exit(0)
    decision = "deny" if policy == "block" else "ask"
    _emit(
        {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": decision,
                "permissionDecisionReason": reason,
            }
        }
    )
    sys.exit(0)


def handle_post_tool_use(data: dict, client: PresidioClient) -> None:
    if _env("PRESIDIO_GUARD_RESULT_REDACTION", "on") != "on":
        sys.exit(0)
    response = data.get("tool_response", None)
    if response is None:
        sys.exit(0)
    redacted, count = client.redact_structure(response)
    if count == 0:
        sys.exit(0)
    output = redacted if isinstance(redacted, str) else json.dumps(redacted)
    _emit(
        {
            "suppressOutput": True,
            "hookSpecificOutput": {
                "hookEventName": "PostToolUse",
                "updatedToolOutput": output,
                "additionalContext": (
                    f"[blackbar] redacted {count} PII value(s) from this "
                    "tool result before you received it. Placeholders like "
                    "<EMAIL_ADDRESS> stand in for the originals."
                ),
            },
        }
    )
    sys.exit(0)


def handle_message_display(data: dict, client: PresidioClient) -> None:
    if _env("PRESIDIO_GUARD_DISPLAY_REDACTION", "off") != "on":
        sys.exit(0)
    delta = data.get("delta", "")
    redacted, spans = client.redact(delta)
    if not spans:
        sys.exit(0)
    _emit(
        {
            "hookSpecificOutput": {
                "hookEventName": "MessageDisplay",
                "displayContent": redacted,
            }
        }
    )
    sys.exit(0)


HANDLERS = {
    "UserPromptSubmit": handle_user_prompt_submit,
    "PreToolUse": handle_pre_tool_use,
    "PostToolUse": handle_post_tool_use,
    "MessageDisplay": handle_message_display,
}


def main() -> None:
    event = sys.argv[1] if len(sys.argv) > 1 else ""
    handler = HANDLERS.get(event)
    if handler is None:
        sys.exit(0)
    try:
        data = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        sys.exit(0)  # malformed payload: never block on our own bug
    client = PresidioClient()
    try:
        handler(data, client)
    except PresidioUnavailable as exc:
        _fail(str(exc))


if __name__ == "__main__":
    main()
