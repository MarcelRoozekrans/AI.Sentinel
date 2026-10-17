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

> **Redaction in 3.0:** the hook CLIs cannot rewrite the request, so a detection configured to `Redact` (the 3.0 default for PII and credentials) falls back to the action of its severity here, and its audit summary ends with `; not redacted`. See [Redaction](../redaction#fallback).

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
| `SENTINEL_EMBEDDING_ENDPOINT` | — | Full embeddings URL, e.g. `https://api.openai.com/v1/embeddings` or `http://localhost:11434/v1/embeddings`. Enables semantic detection |
| `SENTINEL_EMBEDDING_MODEL` | — | Model identifier, e.g. `text-embedding-3-small` or `nomic-embed-text` |
| `SENTINEL_EMBEDDING_API_KEY` | — | Bearer token. Omit for local servers that need none |
| `SENTINEL_EMBEDDING_DIMENSIONS` | — | Vector length, when the model allows a choice |
| `SENTINEL_EMBEDDING_CACHE_DIR` | per-user cache dir | Where reference vectors are cached. Must not be world-writable — see below |

### MCP-specific

| Variable | Default | Purpose |
|---|---|---|
| `SENTINEL_MCP_DETECTORS` | `security` | `security` (13 security detectors plus the 4 Art. 5 compliance detectors — recommended for MCP) or `all` (every detector — higher false-positive rate on structured tool data) |
| `SENTINEL_MCP_MAX_SCAN_BYTES` | `262144` | Truncation cap on tool-result text passed to the detector pipeline. Counts UTF-8 bytes (v1.1+). Full content still forwarded to the host. |
| `SENTINEL_MCP_SCAN_MIMES` (v1.1) | `text/,application/json,application/xml,application/yaml` | MIME allowlist for `resources/read` scanning. Comma-separated. Trailing `/` matches any subtype. Resources outside the allowlist forward verbatim. |
| `SENTINEL_MCP_HTTP_HEADERS` (v1.1) | (none) | `key=value;key=value` headers applied to every HTTP-transport request. For static-token auth (`Authorization=Bearer xyz`). Malformed pairs skipped silently. |
| `SENTINEL_MCP_TIMEOUT_SEC` (v1.1) | `5` | Subprocess shutdown grace in seconds. After this window the proxy logs `transport_dispose action=grace_expired` and returns; the MCP host's own kill policy is the second line of defense. |
| `SENTINEL_MCP_LOG_JSON` (v1.1) | (off) | Set to `1` for NDJSON stderr output. Default is `key=value` lines. Useful when piping proxy logs into a log aggregator. |

## Detector profiles

`SENTINEL_MCP_DETECTORS=security` (default) runs the security detectors that work well on structured MCP tool data, plus the four Art. 5 compliance detectors:

- `SEC-01` PromptInjection
- `SEC-02` CredentialExposure
- `SEC-03` ToolPoisoning
- `SEC-04` DataExfiltration
- `SEC-05` Jailbreak
- `SEC-06` PrivilegeEscalation
- `SEC-07` CovertChannel
- `SEC-09` IndirectInjection
- `SEC-10` AgentImpersonation
- `SEC-19` ToolCallFrequency
- `SEC-21` ExcessiveAgency
- `SEC-22` HumanTrustManipulation
- `SEC-30` ShorthandEmergence
- `CMP-01` to `CMP-04`, the [compliance detectors](../detectors/compliance)

Only `SEC-02` and `SEC-19` and the rule layers of `SEC-01` and `SEC-05` fire without an embedding generator; the rest are semantic and need `SENTINEL_EMBEDDING_ENDPOINT`. A compliance finding is `High`, so `SENTINEL_HOOK_ON_HIGH`, which defaults to `Block`, decides what the proxy does with it.

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

## Behavior change in v1.1

`SENTINEL_MCP_MAX_SCAN_BYTES` now counts UTF-8 bytes, not characters. ASCII content is unchanged; emoji / CJK / accented text reaches the cap sooner. The default `262144` is generous — most tool results fit well under it.

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
