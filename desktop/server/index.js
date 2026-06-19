#!/usr/bin/env node
/*
 * index.js — Presidio MCP server (Node, zero dependencies)
 * ========================================================
 * A stdio JSON-RPC 2.0 MCP server exposing two tools:
 *   presidio_analyze    -> detect PII entities in text
 *   presidio_anonymize  -> replace / redact / mask / hash / encrypt PII
 *
 * Why Node: Claude Desktop bundles a Node runtime, so a node-type .mcpb needs
 * no Python and no extra install. This file uses only Node built-ins
 * (readline, crypto, global fetch in Node 18+), so the bundle ships nothing in
 * node_modules.
 *
 * Detection is delegated to a local Presidio Analyzer HTTP service. The
 * replace/redact/mask/hash operators are applied locally, so only the analyzer
 * service is required. The optional `encrypt` operator calls a Presidio
 * Anonymizer service when PRESIDIO_ANONYMIZER_URL is set.
 *
 * Configuration (env vars):
 *   PRESIDIO_ANALYZER_URL     default http://localhost:5002
 *   PRESIDIO_ANONYMIZER_URL   optional, enables encrypt (e.g. http://localhost:5001)
 *   PRESIDIO_GUARD_OPERATOR   default replace
 *   PRESIDIO_GUARD_LANGUAGE   default en
 *   PRESIDIO_GUARD_THRESHOLD  default 0.5
 *   PRESIDIO_GUARD_ENTITIES   comma list, default all
 *   PRESIDIO_GUARD_TIMEOUT    seconds, default 8
 */

"use strict";

const readline = require("readline");
const crypto = require("crypto");

const PROTOCOL_VERSION = "2024-11-05";
const SERVER_INFO = { name: "blackbar", version: "0.1.0" };

const CFG = {
  analyzerUrl: env("PRESIDIO_ANALYZER_URL", "http://localhost:5002"),
  anonymizerUrl: env("PRESIDIO_ANONYMIZER_URL", ""),
  operator: env("PRESIDIO_GUARD_OPERATOR", "replace"),
  language: env("PRESIDIO_GUARD_LANGUAGE", "en"),
  threshold: parseFloat(env("PRESIDIO_GUARD_THRESHOLD", "0.5")),
  entities: env("PRESIDIO_GUARD_ENTITIES", "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean),
  timeoutMs: parseFloat(env("PRESIDIO_GUARD_TIMEOUT", "8")) * 1000,
};

function env(name, def) {
  const v = process.env[name];
  return v === undefined || v === "" ? def : v;
}

const TOOLS = [
  {
    name: "presidio_analyze",
    description:
      "Detect personally identifiable information (PII) in text using Microsoft Presidio. Returns each entity's type, character span, confidence score, and matched text.",
    inputSchema: {
      type: "object",
      properties: {
        text: { type: "string", description: "Text to scan for PII." },
        language: { type: "string", description: "Language code (default en)." },
        entities: {
          type: "array",
          items: { type: "string" },
          description: "Optional list of entity types to detect; default is all.",
        },
      },
      required: ["text"],
    },
  },
  {
    name: "presidio_anonymize",
    description:
      "Return a copy of the text with PII removed using the chosen operator: replace (<EMAIL_ADDRESS>), redact (delete), mask (****1234), hash, or encrypt (reversible, requires anonymizer service + key).",
    inputSchema: {
      type: "object",
      properties: {
        text: { type: "string" },
        operator: {
          type: "string",
          enum: ["replace", "redact", "mask", "hash", "encrypt"],
          description: "Anonymization operator (default replace).",
        },
        language: { type: "string" },
        entities: { type: "array", items: { type: "string" } },
        key: { type: "string", description: "Encryption key (operator=encrypt only)." },
      },
      required: ["text"],
    },
  },
];

// --------------------------------------------------------------------------- //
// Detection
// --------------------------------------------------------------------------- //
async function analyze(text, language, entities) {
  if (!text || !text.trim()) return [];
  const payload = { text, language: language || CFG.language };
  const ents = entities && entities.length ? entities : CFG.entities;
  if (ents.length) payload.entities = ents;

  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), CFG.timeoutMs);
  let results;
  try {
    const res = await fetch(CFG.analyzerUrl.replace(/\/+$/, "") + "/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      signal: ctrl.signal,
    });
    if (!res.ok) throw new Error(`analyzer returned HTTP ${res.status}`);
    results = await res.json();
  } catch (err) {
    throw new PresidioUnavailable(
      `Presidio analyzer unreachable at ${CFG.analyzerUrl}: ${err.message}`
    );
  } finally {
    clearTimeout(timer);
  }
  return results
    .map((r) => ({
      entity_type: r.entity_type,
      start: r.start,
      end: r.end,
      score: r.score == null ? 1.0 : r.score,
    }))
    .filter((s) => s.score >= CFG.threshold);
}

// --------------------------------------------------------------------------- //
// Local operators
// --------------------------------------------------------------------------- //
function resolveOverlaps(spans) {
  const ordered = [...spans].sort(
    (a, b) => a.start - b.start || b.end - b.start - (a.end - a.start) || b.score - a.score
  );
  const kept = [];
  let lastEnd = -1;
  for (const s of ordered) {
    if (s.start >= lastEnd) {
      kept.push(s);
      lastEnd = s.end;
    }
  }
  return kept.sort((a, b) => b.start - a.start); // apply right-to-left
}

function replacement(original, entityType, operator) {
  switch (operator) {
    case "redact":
      return "";
    case "mask":
      return original.length <= 4
        ? "*".repeat(original.length)
        : "*".repeat(original.length - 4) + original.slice(-4);
    case "hash": {
      const digest = crypto.createHash("sha256").update(original).digest("hex").slice(0, 10);
      return `<${entityType}:${digest}>`;
    }
    default:
      return `<${entityType}>`;
  }
}

function applyOperator(text, spans, operator) {
  let out = text;
  for (const span of resolveOverlaps(spans)) {
    const original = out.slice(span.start, span.end);
    out = out.slice(0, span.start) + replacement(original, span.entity_type, operator) + out.slice(span.end);
  }
  return out;
}

async function encryptViaService(text, spans, key) {
  if (!CFG.anonymizerUrl) {
    return { error: "encrypt requires PRESIDIO_ANONYMIZER_URL to be set." };
  }
  if (!key) return { error: "operator=encrypt requires a 'key'." };
  const body = {
    text,
    anonymizers: { DEFAULT: { type: "encrypt", key } },
    analyzer_results: spans.map((s) => ({
      entity_type: s.entity_type,
      start: s.start,
      end: s.end,
      score: s.score,
    })),
  };
  const res = await fetch(CFG.anonymizerUrl.replace(/\/+$/, "") + "/anonymize", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) return { error: `anonymizer returned HTTP ${res.status}` };
  const data = await res.json();
  return { text: data.text, note: "reversible with the same key" };
}

// --------------------------------------------------------------------------- //
// Tool dispatch
// --------------------------------------------------------------------------- //
async function toolAnalyze(args) {
  const text = args.text || "";
  const spans = await analyze(text, args.language, args.entities);
  const entities = spans.map((s) => ({
    entity_type: s.entity_type,
    start: s.start,
    end: s.end,
    score: Math.round(s.score * 1000) / 1000,
    text: text.slice(s.start, s.end),
  }));
  return JSON.stringify({ count: entities.length, entities }, null, 2);
}

async function toolAnonymize(args) {
  const operator = args.operator || CFG.operator;
  const text = args.text || "";
  const spans = await analyze(text, args.language, args.entities);
  if (operator === "encrypt") {
    return JSON.stringify(await encryptViaService(text, spans, args.key || ""), null, 2);
  }
  const redacted = applyOperator(text, spans, operator);
  return JSON.stringify(
    { text: redacted, entities_found: [...new Set(spans.map((s) => s.entity_type))].sort() },
    null,
    2
  );
}

async function dispatchTool(name, args) {
  try {
    let text;
    if (name === "presidio_analyze") text = await toolAnalyze(args);
    else if (name === "presidio_anonymize") text = await toolAnonymize(args);
    else return { content: [{ type: "text", text: `Unknown tool: ${name}` }], isError: true };
    return { content: [{ type: "text", text }] };
  } catch (err) {
    const msg = err instanceof PresidioUnavailable ? `Presidio unavailable: ${err.message}` : String(err);
    return { content: [{ type: "text", text: msg }], isError: true };
  }
}

// --------------------------------------------------------------------------- //
// JSON-RPC handling
// --------------------------------------------------------------------------- //
async function handle(msg) {
  const { method, id } = msg;
  if (method === "initialize") {
    const requested = (msg.params && msg.params.protocolVersion) || PROTOCOL_VERSION;
    return rpc(id, {
      protocolVersion: requested,
      capabilities: { tools: {} },
      serverInfo: SERVER_INFO,
    });
  }
  if (method === "tools/list") return rpc(id, { tools: TOOLS });
  if (method === "tools/call") {
    const p = msg.params || {};
    const result = await dispatchTool(p.name || "", p.arguments || {});
    return rpc(id, result);
  }
  if (method === "ping") return rpc(id, {});
  if (method && method.startsWith("notifications/")) return null;
  if (id !== undefined && id !== null) {
    return { jsonrpc: "2.0", id, error: { code: -32601, message: `Method not found: ${method}` } };
  }
  return null;
}

function rpc(id, result) {
  return { jsonrpc: "2.0", id, result };
}

class PresidioUnavailable extends Error {}

function main() {
  const rl = readline.createInterface({ input: process.stdin, terminal: false });
  rl.on("line", async (line) => {
    line = line.trim();
    if (!line) return;
    let msg;
    try {
      msg = JSON.parse(line);
    } catch {
      return;
    }
    const response = await handle(msg);
    if (response !== null) process.stdout.write(JSON.stringify(response) + "\n");
  });
}

main();
