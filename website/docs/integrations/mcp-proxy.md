---
sidebar_position: 3
title: MCP proxy
---

# MCP proxy

`AI.Sentinel.Mcp.Cli` is a Model Context Protocol proxy. It sits between an MCP-speaking host (Cursor, Continue, Cline, Windsurf, Copilot's MCP path, Claude Code's MCP integration) and an upstream MCP server. The proxy intercepts tool calls, prompt fetches, and resource reads, runs them through the AI.Sentinel detector pipeline, and blocks threats with a JSON-RPC error to the host.

Unlike the [Claude Code](./claude-code) and [Copilot](./copilot) hooks (which integrate with vendor-specific hook systems), the MCP proxy works with **any** MCP-speaking host — it's pure protocol, vendor-agnostic.

## Install

```bash
dotnet tool install -g AI.Sentinel.Mcp.Cli
```

Installs as `sentinel-mcp` on your `PATH`.

## Wire it into your MCP host

Replace the original `command` for your MCP server with `sentinel-mcp proxy --target <original command>`.

For an MCP server that you'd normally invoke as `uvx mcp-server-filesystem /home/me`:

```json
{
  "mcpServers": {
    "filesystem-guarded": {
      "command": "sentinel-mcp",
      "args": ["proxy", "--target", "uvx", "mcp-server-filesystem", "/home/me"],
      "env": {
        "SENTINEL_HOOK_ON_CRITICAL": "Block",
        "SENTINEL_MCP_DETECTORS": "security"
      }
    }
  }
}
```

The proxy spawns the target command as a subprocess, intercepts MCP protocol messages, and forwards approved ones to the host. Blocked calls return a JSON-RPC error so the host can surface it to the model with proper tool-call-failed semantics.

## What the proxy intercepts

| MCP method | Why scan it |
|---|---|
| `tools/call` | Tool arguments may carry prompt-injection or sensitive data |
| `prompts/get` | Prompt templates may have been poisoned upstream |
| `resources/read` (v1.1) | Document/resource content can carry indirect injection (OWASP LLM01) |

`tools/list`, `prompts/list`, `resources/list`, capability negotiation, and other MCP control-plane messages forward verbatim — no scanning.

## HTTP transports (v1.1)

Beyond stdio, the proxy supports HTTP-transport MCP servers via Streamable HTTP with automatic SSE fallback:

```bash
sentinel-mcp proxy --target https://example.com/mcp
```

When `--target` starts with `http://` or `https://` the proxy uses `HttpClientTransport` instead of spawning a subprocess. Combine with the `SENTINEL_MCP_HTTP_HEADERS` env var for static-token auth.

## Severity → action

Per-MCP-call action mapping uses the same env-var contract as the hook adapters, with optional CLI flag overrides:

```bash
sentinel-mcp proxy --on-critical Block --on-high Block --on-medium Warn --on-low Allow \
                   --target /path/to/server arg1 ...
```

| Source | Precedence |
|---|---|
| CLI flag (`--on-critical Block`) | highest |
| `SENTINEL_MCP_ON_CRITICAL` env var | medium |
| `SENTINEL_HOOK_ON_CRITICAL` (shared with hooks) | low |
| Default (`Block` / `Block` / `Warn` / `Allow`) | lowest |

## Redaction

With `SENTINEL_MCP_REDACT` on, the default, the proxy redacts personal data and secrets in what the target server sends back to the agent, so the model sees `[EMAIL_1_k3f9x2]` in place of the address:

- **`tools/call` results:** text blocks, embedded text resources whose MIME type is in `SENTINEL_MCP_SCAN_MIMES`, and `structuredContent`. 3.0 did not scan embedded resources or `structuredContent`, so these can now produce findings of their own. A value that appears in both `structuredContent` and a text block is counted once per occurrence in the `REDACTED` summary.
- **`prompts/get` messages.**
- **`resources/read` text items** whose MIME type is in `SENTINEL_MCP_SCAN_MIMES`.

Each redaction is recorded as a `REDACTED` audit entry with counts only, and the Allow log line gets `redacted=<n>`.

**PII is restored into later tool calls.** When the agent calls a tool with a PII placeholder the proxy minted earlier in the same run, the tool gets the real value. A lookup followed by an action, such as finding a customer and then mailing them, therefore works. A placeholder stays restorable until `SENTINEL_MCP_REDACT_TTL_MIN` minutes after its last use, 30 by default. The proxy holds up to 10,000 placeholders in memory and evicts the least recently used. An expired or evicted placeholder reaches the tool as literal text.

**Secrets are never restored.** A tool called with `[API_KEY_1_k3f9x2]` gets the placeholder, so a prompt-injected agent cannot send a pasted key to a tool. A tool that needs a secret must get it another way.

Limits:

- **Restored values reach the tool unscanned.** The request scan judges the arguments as the agent sent them, with placeholders, so a restored email address sent to an outbound tool is not flagged on the way out. [Tool-call authorization](../authorization/overview) sees the restored arguments and is the control for outbound tools.
- **Approvals hold real values.** With `RequireApproval`, the approval store, SQLite included, keeps the restored real arguments.
- **Only `tools/call` is restored.** A placeholder in the arguments of `prompts/get` or in a resource URI stays literal text.
- **Tool-call arguments are not redacted.** The proxy judges a call before it runs, so a PII or credential finding in the arguments uses the action of its severity, and its audit summary ends with `; not redacted`. The same holds for blob resources and resources whose MIME type is not allowlisted.
- **The byte budget.** Every allowlisted item is redacted whole, however large. `SENTINEL_MCP_MAX_SCAN_BYTES` is the scan budget of one tool result, prompt or resource item: the detectors scan its first bytes, and content over it is reported as [`SEC-00`](#scan-budget), which blocks it under the default `OnCritical`.
- **Fallbacks.** When a scan is rate limited, or the pipeline throws, the content is forwarded unredacted, as 3.0 forwarded it unscanned. The rate-limited case is logged with `reason=rate_limited`.

See [Redaction → Per surface](../redaction#per-surface) for how this compares with the hook CLIs and the in-process client.

## Environment variables

### Shared with hook adapters

| Variable | Default | Purpose |
|---|---|---|
| `SENTINEL_HOOK_ON_CRITICAL` | `Block` | Action for Critical |
| `SENTINEL_HOOK_ON_HIGH` | `Block` | Action for High |
| `SENTINEL_HOOK_ON_MEDIUM` | `Warn` | Action for Medium |
| `SENTINEL_HOOK_ON_LOW` | `Allow` | Action for Low |
| `SENTINEL_HOOK_VERBOSE` | `false` | Stderr diagnostic per call |
| `SENTINEL_HOOK_SUPPRESS_SEMANTIC_WARNING` | `false` | Suppress the inert-semantic-detection warning |
| `SENTINEL_HOOK_COMPLIANCE` | `off` | Fallback for `SENTINEL_MCP_COMPLIANCE` |
| `SENTINEL_HOOK_REDACT` | `on` | Fallback for `SENTINEL_MCP_REDACT` |
| `SENTINEL_EMBEDDING_ENDPOINT` | — | Full embeddings URL, e.g. `https://api.openai.com/v1/embeddings` or `http://localhost:11434/v1/embeddings`. Enables semantic detection |
| `SENTINEL_EMBEDDING_MODEL` | — | Model identifier, e.g. `text-embedding-3-small` or `nomic-embed-text` |
| `SENTINEL_EMBEDDING_API_KEY` | — | Bearer token. Omit for local servers that need none |
| `SENTINEL_EMBEDDING_DIMENSIONS` | — | Vector length, when the model allows a choice |
| `SENTINEL_EMBEDDING_CACHE_DIR` | per-user cache dir | Where reference vectors are cached. Must not be world-writable — see below |
| `SENTINEL_REVIEW_ENDPOINT` | — | Full chat completions URL of the second-stage reviewer, e.g. `https://api.openai.com/v1/chat/completions` or `http://localhost:11434/v1/chat/completions`. Without a reviewer, semantic detections are capped at Medium and only warn |
| `SENTINEL_REVIEW_MODEL` | — | Model identifier of the reviewer. Required with the endpoint |
| `SENTINEL_REVIEW_API_KEY` | — | Bearer token. Omit for local servers that need none |
| `SENTINEL_REVIEW_MAX_PER_SCAN` | `4` | Reviews per scan. `0` turns the review off |
| `SENTINEL_REVIEW_TIMEOUT_MS` | `5000` | Per-review timeout in milliseconds |

**What the review endpoint receives.** `SENTINEL_REVIEW_ENDPOINT` is sent each flagged text, up to its last 64 KiB. That text can contain the secret or personal data a credential or PII detector flagged, just as the embedding endpoint receives the texts it embeds, so choose a provider you would trust with that data, or a local one. The reviewer's reason comes back the other way: it becomes part of the finding's reason, which the proxy's block error passes on to the agent. It is sanitised to one line and capped at 200 characters.

### MCP-specific

| Variable | Default | Purpose |
|---|---|---|
| `SENTINEL_MCP_DETECTORS` | `security` | `security` (16 security detectors plus the 4 Art. 5 compliance detectors, which run only with `SENTINEL_MCP_COMPLIANCE=on` — recommended for MCP) or `all` (every detector — higher false-positive rate on structured tool data). Unset, falls back to `SENTINEL_HOOK_DETECTORS`, then to `security` |
| `SENTINEL_MCP_COMPLIANCE` | `off` | `on` / `1` / `true` / `yes` → run the four Art. 5 [compliance detectors](../detectors/compliance), which are off by default; `off` / `0` / `false` / `no` keeps them off. Unset, falls back to `SENTINEL_HOOK_COMPLIANCE`. Thresholds are code-only |
| `SENTINEL_MCP_REDACT` | `on` | `on` / `1` / `true` / `yes` or `off` / `0` / `false` / `no` → turn [redaction](#redaction) on or off. Anything else, or unset, falls back to `SENTINEL_HOOK_REDACT`, then to on |
| `SENTINEL_MCP_REDACT_TTL_MIN` | `30` | Minutes a PII placeholder stays restorable into tool calls after its last use. A positive integer; anything else keeps the default |
| `SENTINEL_MCP_MAX_SCAN_BYTES` | `262144` | The proxy's `SentinelOptions.MaxScanBytes`, in UTF-8 bytes: the scan budget of each tool call, tool result and prompt, and of each `resources/read` item. Content over it is blocked as `SEC-00` under the default `OnCritical`; see [Scan budget](#scan-budget). A positive integer; anything else, or unset, falls back to `SENTINEL_HOOK_MAX_SCAN_BYTES`, then to the default |
| `SENTINEL_MCP_SCAN_MIMES` (v1.1) | `text/,application/json,application/xml,application/yaml` | MIME allowlist for `resources/read` scanning. Comma-separated. Trailing `/` matches any subtype. Resources outside the allowlist forward verbatim. |
| `SENTINEL_MCP_HTTP_HEADERS` (v1.1) | (none) | `key=value;key=value` headers applied to every HTTP-transport request. For static-token auth (`Authorization=Bearer xyz`). Malformed pairs skipped silently. |
| `SENTINEL_MCP_TIMEOUT_SEC` (v1.1) | `5` | Subprocess shutdown grace in seconds. After this window the proxy logs `transport_dispose action=grace_expired` and returns; the MCP host's own kill policy is the second line of defense. |
| `SENTINEL_MCP_LOG_JSON` (v1.1) | (off) | Set to `1` for NDJSON stderr output. Default is `key=value` lines. Useful when piping proxy logs into a log aggregator. |

## Detector profiles

`SENTINEL_MCP_DETECTORS=security` (default) runs the security detectors that work well on structured tool data, plus the four Art. 5 compliance detectors when `SENTINEL_MCP_COMPLIANCE=on`. The hook CLIs `sentinel-hook` and `sentinel-copilot-hook` run the same preset by default, set by `SENTINEL_HOOK_DETECTORS`:

- `SEC-01` PromptInjection
- `SEC-02` CredentialExposure
- `SEC-03` ToolPoisoning
- `SEC-04` DataExfiltration
- `SEC-05` Jailbreak
- `SEC-06` PrivilegeEscalation
- `SEC-07` CovertChannel
- `SEC-08` EntropyCovertChannel
- `SEC-09` IndirectInjection
- `SEC-10` AgentImpersonation
- `SEC-19` ToolCallFrequency
- `SEC-21` ExcessiveAgency
- `SEC-22` HumanTrustManipulation
- `SEC-23` PiiLeakage
- `SEC-24` AdversarialUnicode
- `SEC-30` ShorthandEmergence
- `CMP-01` to `CMP-04`, the [compliance detectors](../detectors/compliance)

Only `SEC-02`, `SEC-08`, `SEC-19`, `SEC-23` and `SEC-24` and the rule layers of `SEC-01` and `SEC-05` fire without an embedding generator; the rest are semantic and need `SENTINEL_EMBEDDING_ENDPOINT`. The compliance detectors are off unless `SENTINEL_MCP_COMPLIANCE=on`. When on, they carry the `Alert` action, so a compliance finding is written to the audit log and the call forwards, as with `Warn`, whatever `SENTINEL_HOOK_ON_HIGH` says. Every other detector follows the `SENTINEL_HOOK_ON_*` mapping.

`SEC-02` and `SEC-23` are also the redactors: [redaction](#redaction) takes them from the preset, so a preset without `SEC-23` would redact secrets but not personal data. Until `SEC-23` joined this preset, that was the case for the default.

One rule-based security detector stays out of the preset: `SEC-32` SystemPromptEcho compares the model's output with its system prompt, and the proxy sees neither.

`SENTINEL_MCP_DETECTORS=all` runs every detector including operational and hallucination — useful in some adversarial-testing scenarios but generates false positives on structured JSON tool calls (`OPS-04 PlaceholderText` may flag an "Insert here" string in a code-completion result).

## Auth

`SENTINEL_MCP_HTTP_HEADERS` covers **static-token auth only** — bearer tokens, API keys, tenant headers:

```bash
SENTINEL_MCP_HTTP_HEADERS="Authorization=Bearer abc123;X-Tenant=acme"
```

OAuth2 flows and mTLS client certificates are **not** supported in v1.1 — see the deferred items in [BACKLOG](https://github.com/MarcelRoozekrans/AI.Sentinel/blob/main/docs/BACKLOG.md) if you need them.

## Logging

Default stderr format is grep-friendly `key=value` lines:

```
[sentinel-mcp] event=tools/call decision=Block detector=SEC-01 severity=Critical
[sentinel-mcp] event=resources/read decision=Allow mime=application/json bytes=4096
```

Set `SENTINEL_MCP_LOG_JSON=1` for NDJSON output (one log record per line) — easier for log aggregators to parse than the default key=value form.

## Audit

The proxy records findings, authorization denials and approval holds to `ai-sentinel/audit.db` under the per-user data folder by default, with `Source` set to `mcp`. Allowed calls are not recorded. The file is shared with `sentinel-hook` and `sentinel-copilot-hook`. All entries from one proxy run share one session id. On Linux and macOS the directory is created `0700` and the files `0600`.

Approval decisions the proxy observes, such as an approval wait that times out or a grant that expires, are recorded in the same file. The proxy opens the audit file before it reads `SENTINEL_APPROVAL_CONFIG`, so a malformed approval config also creates the audit file before the proxy exits with code 1.

| Variable | Default | Purpose |
|---|---|---|
| `SENTINEL_MCP_AUDIT_SQLITE` | `<data folder>/ai-sentinel/audit.db` | A database path, or `off` (any case) for the in-memory ring buffer |
| `SENTINEL_MCP_AUDIT_NDJSON` | — | A file path. Adds an NDJSON copy of every entry |
| `SENTINEL_MCP_AUDIT_MAX_MB` | `100` | Size cap in megabytes, enforced when the proxy opens the file. `0` means no cap |

An audit failure never changes a decision. The proxy logs it on stderr as an `audit_unavailable` event:

```
event=audit_unavailable detail=...
```

Browse the file with `sentinel dashboard` from the `AI.Sentinel.Cli` tool; see [Claude Code → Audit destination](./claude-code#audit-destination).

## Capability mirroring (v1.1)

The proxy mirrors target server capabilities — it only advertises `tools` / `prompts` / `resources` to the host when the upstream target advertises them. So if your filesystem MCP server doesn't expose `prompts`, the proxy doesn't either, and the host's `prompts/list` calls return cleanly empty rather than confusingly "supported but empty".

## Subprocess lifecycle (v1.1)

When the host disconnects (SIGTERM, host shutdown), the proxy:

1. Sends SIGTERM to the upstream subprocess
2. Waits up to `SENTINEL_MCP_TIMEOUT_SEC` for the subprocess to exit cleanly
3. Logs `transport_dispose action=grace_expired` if the subprocess overruns
4. Returns control to the host's process supervisor

The proxy doesn't currently SIGKILL the subprocess on grace expiry — `StdioClientTransport` doesn't expose its `Process` handle. SIGKILL on grace expiry is on the [backlog](https://github.com/MarcelRoozekrans/AI.Sentinel/blob/main/docs/BACKLOG.md). Today, your MCP host's own process supervisor or the OS handles eventually-stuck subprocesses.

## Scan budget

`SENTINEL_MCP_MAX_SCAN_BYTES` sets `SentinelOptions.MaxScanBytes` of the proxy's pipeline, and the pipeline is the one place that cuts. A tool call's arguments, a tool result, a prompt and each resource item are passed to it whole. A tool result's structured content that a text block of the result repeats exactly, as the MCP specification has a tool do, is still redacted but is scanned once, through the text block, so it does not count against the budget twice. Structured content that holds a JSON escape, such as `\u0069` or `\n`, is always scanned as well, decoded, because the escape can hide what the text block shows only in its raw form. When one is over the budget, the detectors scan its first `SENTINEL_MCP_MAX_SCAN_BYTES` bytes and the pipeline adds one `Critical` [`SEC-00`](../detectors/overview#scan-budget-and-sec-00) finding that gives both byte counts. Its action is `OnCritical`, so under the default `SENTINEL_MCP_ON_CRITICAL=Block` the agent gets the JSON-RPC error `Blocked by AI.Sentinel: SEC-00 Critical: New content is … bytes; only the first … were scanned.`, and the finding is audited.

**Behaviour change.** Until #439 the proxy truncated the scan text to the budget and forwarded the rest unscanned, so text after the budget, an injection included, reached the agent. A redacting scan forwarded an item that did not fit unredacted, and `resources/read` skipped such an item with `reason=oversize`. Content over the budget is now blocked: tool-call arguments, tool results, prompts and resource items alike, so a `tools/call` whose arguments are over the budget is refused before it reaches the server. Raise `SENTINEL_MCP_MAX_SCAN_BYTES` for servers that send or return large content. Setting `SENTINEL_MCP_ON_CRITICAL=Warn` forwards such content with a warning, but it downgrades every `Critical` finding, prompt injection and credential exposure included, not only `SEC-00`, so prefer raising the budget.

Since v1.1 the budget counts UTF-8 bytes, not characters: emoji, CJK and accented text reach it sooner than ASCII.

## Programmatic use

The `sentinel-mcp` CLI is the supported entry point. The `AI.Sentinel.Mcp` package is the library the CLI is built on; its proxy machinery is internal, and embedding the proxy in a custom MCP host is not a supported public API in 3.0. To put Sentinel in front of an MCP server, run `sentinel-mcp` as the server command your host launches.

## When to use this vs. the hook adapters

| Scenario | Use |
|---|---|
| Claude Code | [Hook adapter](./claude-code) — tighter integration, scans prompts not just MCP traffic |
| GitHub Copilot | [Hook adapter](./copilot) — same as Claude Code |
| Cursor / Continue / Cline / Windsurf | **MCP proxy** — vendor-neutral, scans every MCP server they connect to |
| Multi-host development environment | **MCP proxy** — one config across all MCP-aware tools |
| Custom MCP-speaking agent | **MCP proxy** — drop-in protocol-level shim |

The hook adapters and the MCP proxy can coexist. A typical Cursor + Copilot setup would have both — Copilot hooks for the IDE-level interactions, MCP proxy in front of every MCP server both tools talk to.

## Next: [Authorization → overview](../authorization/overview) — preventive controls for tool calls
