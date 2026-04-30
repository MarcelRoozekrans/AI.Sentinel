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
  "tenantId": null,
  "databasePath": "/var/lib/ai-sentinel/approvals.db",
  "defaultGrantMinutes": 15,
  "defaultJustificationTemplate": "Tool {tool} requested by {caller}",
  "includeConversationContext": false,
  "tools": {
    "delete_database":  { "role": "DBA" },
    "send_payment":     { "role": "Treasury", "grantMinutes": 5, "requireJustification": true },
    "deploy_*":         { "role": "DeployApprover" }
  }
}
```

### Top-level fields

| Field | Type | Required | Notes |
|---|---|---|---|
| `backend` | string | yes | One of `none`, `in-memory`, `sqlite`, `entra-pim`. |
| `tenantId` | string | required for `entra-pim` | Entra tenant GUID. |
| `databasePath` | string | required for `sqlite` | Absolute path to the `.db` file. WAL/SHM sidecars created next to it. |
| `defaultGrantMinutes` | int | yes | Per-tool `grantMinutes` overrides. |
| `defaultJustificationTemplate` | string | yes | Currently informational; per-tool override planned. |
| `includeConversationContext` | bool | yes | Forwarded to backend (currently informational). |
| `tools` | map | yes | Pattern → binding. Keys are tool-name patterns (glob-style with `*`). |

### Per-tool fields

| Field | Type | Required | Notes |
|---|---|---|---|
| `role` | string | yes | Backend-specific binding — DBA group, PIM role name, etc. Set on `ApprovalSpec.BackendBinding`. |
| `grantMinutes` | int? | no | Override `defaultGrantMinutes`. |
| `requireJustification` | bool? | no | Default `true`. |

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
