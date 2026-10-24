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
| `when` | object | no | none | Conditions on the tool arguments. Keys are JSON paths, values are regexes, and all must hold. An empty object is a config error. No `when` means the rule matches every call to the tool. See [Argument conditions](#argument-conditions). |
| `grantScope` | string | no | `"rule"` | `"rule"` or `"call"`. See [Grant scope](#grant-scope). |

A tool key holds one object, as above, or an array of objects. See [Several rules per tool](#several-rules-per-tool).

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

## Several rules per tool

A generic tool often needs more than one rule: a reviewer for ordinary destructive calls and a stricter approver for the dangerous ones. Give the tool key an array instead of an object:

```json
"tools": {
  "Bash": [
    {
      "role": "ProdOps",
      "grantScope": "call",
      "when": { "$.command": "\\bkubectl\\b.*\\bdelete\\b.*\\b(prod|production)\\b" }
    },
    { "role": "Operator", "when": { "$.command": "\\bkubectl\\s+delete\\b" } }
  ]
}
```

The first entry whose `when` holds, or that has no `when`, is the rule for the call. The entries after it are skipped, so put the most specific rule first.

- A call to the tool is governed as soon as the tool name matches the key, even when no entry's `when` holds. Under `DefaultToolPolicy = Deny` a narrow `Bash` rule therefore does not start denying other `Bash` calls: a call that matches no entry simply needs no approval.
- An array must not be empty.
- An entry without `when` matches everything, so it must be the last entry. An entry after it is unreachable and is a config error.
- Each entry is its own policy. A grant for the `Operator` entry never covers the `ProdOps` entry. See [Policy names](#policy-names).

A single object behaves as before. It is the same as an array of one entry.

## Argument conditions

`when` maps a JSON path into the tool arguments to a regex. The rule applies only when every condition holds. The tool arguments are the JSON object the agent sent with the call.

```json
"tools": {
  "mcp__api__http_request": {
    "role": "Operator",
    "when": { "$.method": "^(POST|PUT|PATCH|DELETE)$" }
  },
  "mcp__ops__invoke_action": {
    "role": "Operator",
    "when": { "$.action": "^(delete|purge|disable)_" }
  }
}
```

Reads through `mcp__api__http_request` (`GET`) pass without approval. Writes need an `Operator`. Several conditions in one `when` are combined with AND:

```json
"when": { "$.method": "^DELETE$", "$.path": "^/(accounts|billing)/" }
```

### Path syntax

A path is `$` followed by any sequence of:

| Segment | Meaning |
|---|---|
| `.name` | Property `name` of an object. |
| `['name']` | Property with a name that has dots, spaces or quotes, such as `$['content-type']`. Inside the quotes, `\'` is a quote and `\\` is a backslash. Any other backslash sequence is a config error. In a JSON file the backslashes are doubled again. |
| `[n]` | Element `n` of an array, counting from 0. |

Wildcards, filters, recursive descent and slices are not supported. A bad path is a config error at load.

### What the regex sees

| JSON value at the path | Matched text |
|---|---|
| string | The string value, unescaped. |
| number, `true`, `false` | The raw JSON token, such as `42` or `true`. |
| object or array | The compact raw JSON text. |
| `null`, or the path does not exist | The condition does not hold. |

A condition never matches a field the call did not send. A rule that must also gate calls lacking a field can say so with a separate entry that has no condition on that field.

### Regex rules

- Regexes are case-sensitive. Start a pattern with `(?i)` for case-insensitive matching.
- Matching is unanchored, like `Regex.IsMatch`. Use `^...$` for an exact value.
- Inside a JSON string every backslash is doubled, so `\bkubectl\s+delete\b` is written `"\\bkubectl\\s+delete\\b"`.
- An invalid regex is a config error at load. The message names the tool key, the entry index and the path.
- Matching uses the invariant culture and never hangs: patterns run without backtracking where the pattern allows it, otherwise under a 100 ms timeout.

### Fail closed

A rule never silently stops gating. In each of these cases every condition of the entry counts as holding, so the call needs approval:

- a regex hits its timeout (the guard also logs a warning naming the rule);
- the arguments are not a JSON object or array, for example an unparsed string or no arguments at all;
- a string at the path cannot be decoded, for example a lone surrogate escape;
- the path meets a duplicate key.

### Not a sandbox

A `when` rule reduces approval noise for cooperative agents. It is not a security boundary. A regex on a shell command can be evaded with quoting, aliases, variables or `sh -c`:

```bash
# Matched by \bkubectl\s+delete\b, so it needs approval:
kubectl delete ns prod

# Not matched, but does the same thing:
k=kubectl; $k delete ns prod
```

For `Bash`, treat the rule as a speed bump for the agent that behaves, and keep real isolation in credentials and permissions of the account the commands run as.

## Grant scope

An approved request grants access for `grantMinutes`. By default (`"grantScope": "rule"`) the grant covers every call that matches the same rule in that time, whatever its arguments.

With `"grantScope": "call"` the grant is tied to the exact arguments that were approved. The approver sees the arguments in the request, approves exactly those, and a retry with the same arguments hits the grant. The arguments are compared after normalization: key order and whitespace do not matter. A retry with any other arguments starts a new request.

```json
"mcp__ops__invoke_action": {
  "role": "Operator",
  "grantScope": "call",
  "when": { "$.action": "^(delete|purge|disable)_" }
}
```

`"call"` needs a backend that stores a grant per request. The Entra PIM backend cannot use it, because a PIM grant is a role activation and cannot be tied to arguments. `grantScope: "call"` with `backend: entra-pim` is a config error at load.

## Policy names

Every approval rule is a policy with a name. The name keys the request and its grant in the store, and it shows in the dashboard, the audit log and the receipt:

| Rule | Policy name |
|---|---|
| A single object, or entry 0 of an array | `approval:<pattern>`, for example `approval:Bash` |
| Entry `i` (1 or higher) of an array | `approval:<pattern>[i]`, for example `approval:Bash[1]` |
| Any of the above with `grantScope: "call"` | The name followed by `#` and 16 hex characters, the fingerprint of the canonical arguments |

An existing config file keeps its policy names, so pending requests and active grants survive an upgrade. Turning an object into a one-element array keeps them too.

The receipt the CLI prints names the rule that matched, for example `Rule: approval:Bash[1]`.

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
- An empty `tools` array, an empty `when`, an invalid path or regex, or an unknown `grantScope` → fail.
- An entry without `when` that is not last in its array → fail.
- `grantScope: "call"` with `backend=entra-pim` → fail.

Validation failures print to stderr and exit `1`. Successful load is silent.

## See also

- [In-memory backend](/docs/approvals/in-memory) — the default.
- [SQLite backend](/docs/approvals/sqlite) — persistent, single-host.
- [Entra PIM backend](/docs/approvals/entra-pim) — enterprise.
