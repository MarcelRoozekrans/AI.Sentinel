---
sidebar_position: 6
title: CLI config file
---

# CLI approval config

The three CLIs (`sentinel-hook`, `sentinel-copilot-hook`, `sentinel-mcp`) read approval config from a JSON file pointed to by the `SENTINEL_APPROVAL_CONFIG` environment variable. Source-editing isn't an option for CLI users, so the config file is the only public surface.

## Enabling

```bash
export SENTINEL_APPROVAL_CONFIG=/etc/ai-sentinel/approvals.json
sentinel-hook user-prompt-submit < input.json
```

If the env var is unset (or empty), approvals are disabled — the CLI behaves exactly as it did pre-Stage-5.

## File shape

```json
{
  "backend": "sqlite",
  "databasePath": "/var/lib/ai-sentinel/approvals.db",
  "defaultGrantMinutes": 15,
  "tools": {
    "delete_database":  { "role": "DBA" },
    "send_payment":     { "role": "Treasury", "grantMinutes": 5, "requireJustification": true },
    "deploy_*":         { "role": "DeployApprover" }
  }
}
```

### Top-level fields

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `backend` | string | yes | — | One of `none`, `in-memory`, `sqlite`, `entra-pim`. |
| `tenantId` | string | for `entra-pim` only | — | Entra tenant GUID. |
| `databasePath` | string | for `sqlite` only | — | Absolute path to the `.db` file. WAL/SHM sidecars created next to it. |
| `defaultGrantMinutes` | int | no | `15` | Must be `> 0`. Per-tool `grantMinutes` overrides this. |
| `defaultJustificationTemplate` | string | no | `"AI agent invocation: {tool}"` | Currently informational; per-tool override planned. |
| `includeConversationContext` | bool | no | `true` | Forwarded to backend (currently informational). |
| `tools` | map | no | empty | Pattern → binding. Keys are tool-name patterns (glob-style with `*`). |

### Per-tool fields

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `role` | string | yes | — | Backend-specific binding — DBA group, PIM role name, etc. Set on `ApprovalSpec.BackendBinding`. |
| `grantMinutes` | int? | no | `defaultGrantMinutes` | Override the top-level default. |
| `requireJustification` | bool? | no | `true` | |

### Environment-variable interpolation

Values containing `${VAR}` are expanded against process environment variables at load time. Unset variables expand to empty string. Useful for committing sample configs without baking in tenant IDs or absolute paths:

```json
{
  "backend": "entra-pim",
  "tenantId": "${SENTINEL_ENTRA_TENANT}",
  "tools": { "delete_database": { "role": "DBA" } }
}
```

Escaping (`$${VAR}`) is not currently supported — there's been no real-world need.

## Per-CLI behavior on `RequireApproval`

| CLI | When the guard returns `RequireApproval` |
|---|---|
| `sentinel-hook` (Claude Code) | Deny-with-receipt — exits `2` with the request ID + approval URL on stderr. User approves out-of-band, then re-runs the prompt. |
| `sentinel-copilot-hook` | Same: deny-with-receipt. |
| `sentinel-mcp` (proxy) | **Wait-and-block** when `SENTINEL_MCP_APPROVAL_WAIT_SEC=N` is set (positive integer). Otherwise **fail-fast** — emits the receipt as a JSON-RPC error and the agent decides whether to retry. |

```bash
# MCP: wait up to 5 minutes for approval before failing the tool call.
export SENTINEL_MCP_APPROVAL_WAIT_SEC=300
sentinel-mcp proxy --target /usr/local/bin/my-mcp-server
```

## Validation

The config loader validates required fields at startup:

- `backend=sqlite` without `databasePath` → fail.
- `backend=entra-pim` without `tenantId` → fail.
- Unknown `backend` value → fail.
- Per-tool `role` empty → fail.

Validation failures print to stderr and exit `1`. Successful load is silent.

## See also

- [In-memory backend](/docs/approvals/in-memory) — the default.
- [SQLite backend](/docs/approvals/sqlite) — persistent, single-host.
- [Entra PIM backend](/docs/approvals/entra-pim) — enterprise.
