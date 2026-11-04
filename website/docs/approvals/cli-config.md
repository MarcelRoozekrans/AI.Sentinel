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
| `notifyUrl` | string | no | none | Absolute `http` or `https` URL that receives a POST for each new request. No value turns the webhook off. See [Notify on new requests](#notify-on-new-requests). |
| `notifyHeaders` | object | no | empty | Extra request headers, name to string value. Needs `notifyUrl`. |
| `notifyIncludeArgs` | bool | no | `false` | Send the redacted tool arguments. Needs `notifyUrl`. |
| `dashboardUrl` | string | no | none | Absolute `http` or `https` URL of your dashboard, including the path prefix, for example `https://dash.example.com/ai-sentinel/`. The message text links to it. |
| `semantic` | object | no | none | Asks for approval when a tool call is close in meaning to an example of a destructive call. See [Semantic approvals](#semantic-approvals). |

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
      "when": { "$.command": "\\bkubectl\\b[\\s\\S]*\\bdelete\\b[\\s\\S]*\\b(prod|production)\\b" }
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
| `.name` | Property `name` of an object. The name may contain only letters, digits, `_` and `-`; anything else needs `['name']`. |
| `['name']` | Property with a name that has dots, spaces or quotes, such as `$['content-type']`. Inside the quotes, `\'` is a quote and `\\` is a backslash. Any other backslash sequence is a config error. In a JSON file the backslashes are doubled again. |
| `[n]` | Element `n` of an array, counting from 0. |

A bare `$` is rejected. Wildcards, filters, recursive descent and slices are not supported. A bad path is a config error at load.

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
- `.` does not match a newline, and a command or a file body can span lines. To join parts of a value that may sit on different lines, use `[\s\S]*` instead of `.*`, as the examples on this page do.
- Inside a JSON string every backslash is doubled, so `\bkubectl\s+delete\b` is written `"\\bkubectl\\s+delete\\b"`.
- An invalid regex is a config error at load. The message names the tool key, the entry index for arrays, and the path.
- Matching uses the invariant culture and never hangs: patterns run without backtracking where the pattern allows it, otherwise under a 100 ms timeout.

### Fail closed

A rule never silently stops gating. Two kinds of case fail closed.

Arguments that are not a JSON object or array, for example an unparsed string or no arguments at all: every condition of every entry with a `when` counts as holding, so the call needs approval.

A single condition that cannot be decided: only that condition counts as holding, and the entry's other conditions are still evaluated normally. The cases are:

- a regex hits its timeout;
- a string at the path cannot be decoded, for example a lone surrogate escape;
- the path meets a duplicate key.

The guard logs a warning naming the rule for these. For example, with `{"$.method": "^DELETE$", "$.path": "..."}`, a `GET` call whose path condition times out does not match the rule, because the method condition does not hold.

### Not a sandbox

A `when` rule reduces approval noise for cooperative agents. It is not a security boundary. A regex on a shell command can be evaded with quoting, aliases, variables or `sh -c`:

```bash
# Matched by \bkubectl\s+delete\b, so it needs approval:
kubectl delete ns prod

# Not matched, but does the same thing:
k=kubectl; $k delete ns prod
```

For `Bash`, treat the rule as a speed bump for the agent that behaves, and keep real isolation in credentials and permissions of the account the commands run as.

## Semantic approvals

Regex rules miss rephrased calls. `\bkubectl\s+delete\b` does not match `kubectl -n prod delete ns billing`, and the config can only list the spellings you thought of. The `semantic` block adds a second layer: it compares the text of a tool call with examples of destructive calls by embedding both, and asks for approval when the call is close in meaning to an example. It can only add approvals. It never allows a call that a rule or a policy denies.

```json
{
  "backend": "sqlite",
  "databasePath": "/var/lib/ai-sentinel/approvals.db",
  "tools": {
    "Bash": { "role": "ProdOps", "when": { "$.command": "\\bkubectl\\s+delete\\b" } }
  },
  "semantic": {
    "threshold": 0.80,
    "examples": ["kubectl delete namespace", "decommission a tenant"],
    "replaceExamples": false,
    "tools": {
      "Bash": { "role": "Operator" },
      "mcp__api__http_request": { "role": "Operator", "grantMinutes": 30 }
    }
  }
}
```

It needs an embedding generator. The CLIs read it from the `SENTINEL_EMBEDDING_*` variables, see [Claude Code](/docs/integrations/claude-code). Without one the layer is inert: nothing is scored and a warning says so. The hooks print `Semantic approvals are configured but no embedding generator is; the semantic layer is inert.` on stderr. `sentinel-mcp` writes it as a log line with `event=semantic_approval_inert`. A host that calls `AddAISentinel` in code gets the same warning in its log.

### Block fields

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `tools` | object | yes | none | Tool pattern to binding, same pattern syntax as the top-level `tools`. The first matching key in file order covers the call. Must not be empty. |
| `threshold` | number | no | `0.80` | Cosine similarity needed for a match, above 0 and at most 1. |
| `examples` | string[] | no | none | Added to the built-in examples. A blank entry is a config error. |
| `replaceExamples` | bool | no | `false` | `true` drops the built-in examples and uses only `examples`, which must then not be empty. |

### Per-tool fields

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `role` | string | yes | none | Backend binding, as for a rule. |
| `grantMinutes` | int | no | `defaultGrantMinutes` | Must be above 0. |
| `requireJustification` | bool | no | `true` | |
| `paths` | string[] | no | see below | The text to score, as [paths](#path-syntax). Must not be empty. |
| `threshold` | number | no | the block's | Overrides the block threshold for this tool. |

`grantScope` is not accepted, because a semantic grant is always tied to the approved call. Unknown keys in the block or in a binding are config errors, with the key named. `semantic` with `backend: entra-pim` or `backend: none` is a config error: a PIM grant cannot be tied to arguments, and `none` has no store to ask. Listing a tool under `semantic` does not make it governed: under `DefaultToolPolicy = Deny` an unbound tool is still denied.

### Which text is scored

With `paths`, each path is scored on its own, using the same [value table](#what-the-regex-sees) as `when`. A missing or `null` value gives no text. Without `paths`:

| Tool | Scored text |
|---|---|
| `Bash`, `bash`, `powershell` | `$.command` |
| any other tool | the whole arguments as compact JSON |

Tool names are matched ordinally. `"Bash"` is Claude Code's shell tool and `"bash"` is Copilot's, and a key for one does not cover the other. List both when both CLIs use the config. Arguments that are not a JSON object or array are scored as their raw text. A call with no text to score is not flagged. Each text is cut to `MaxScanBytes` at a UTF-8 boundary, and the reason says so.

Each path is scored separately. `"paths": ["$.method", "$.url"]` scores `DELETE` and the URL as two texts and can never match an example such as `DELETE https://api.example.com/v1/users`. For HTTP tools keep the default, which scores the whole JSON, or write examples per field.

### Where it runs

The semantic layer runs last. If a rule or a policy already decides the call (approval needed, deny), that decision stands and nothing is scored. If a rule applied to the call and its grant is active, the call is allowed without a semantic check, because the approver already approved a rule that covers it. Otherwise the call is scored, and a match asks for approval under the policy name `semantic:<key>#<fingerprint>`, where `<key>` is the `semantic.tools` key and the fingerprint is the one described under [Policy names](#policy-names). Approving covers only that tool and those exact arguments, for `grantMinutes`.

### What the approver sees

A semantic request carries a `Reason`, for example `Semantic match 0.87 ≥ 0.80 on $.command: "kubectl delete namespace production"`: the score, the threshold, the path of the text and the closest example. It shows as "Why approval is needed" on the [dashboard](/docs/approvals/dashboard) request page, as a `Reason:` line in the receipt, and as `reason` in the [webhook](#payload) body. Rule-based requests have no reason. Like the arguments, the reason is redacted on the dashboard page.

### Fail closed

When the call cannot be scored, it asks for approval instead of passing. The cases are an error from the embedding generator, a timeout, a wrong number of vectors, an empty or invalid vector, and a vector of the wrong size. The request has the reason `Semantic check failed: <kind>; approval required (fail closed)`. It has the same policy name as a match, so after the provider recovers a retry of the same call is covered by the grant. There is no switch to fail open. The timeout is the embedding provider's own.

### How well it works

Read this before you rely on the defaults. The built-in examples and the default threshold were tuned with `all-MiniLM-L6-v2`. On a held-out set of 35 destructive calls written as paraphrases of the examples, through other tools, flag spellings, shell wrappers and API calls, the default flags 2 (6 %). Of 33 held-out benign calls none was flagged, and the highest benign score was 0.7916 (`git pull --rebase origin main`), just under the threshold of 0.80. The layer catches close variants of the built-in commands, such as `kubectl delete namespace payments-prod` or `terraform apply -destroy -auto-approve`. Embeddings judge topic more than intent, so a paraphrase through another tool scores low. A different embedding model needs its own run.

To get more out of it:

- Add examples phrased the way your team's destructive calls look, in `examples`.
- Tune the threshold on your own texts. Put destructive and benign samples in a copy of `tools/AI.Sentinel.ComplianceEval/approval-phrases.json` and run `dotnet run --project tools/AI.Sentinel.ComplianceEval -- --approvals path/to/approval-phrases.json --model all-MiniLM-L6-v2`. Without a path it uses the bundled file. The report shows the score distribution, the lowest threshold above every held-out benign score, and the recall at it.

Lowering the threshold catches more and also flags more harmless calls. At 0.78 the held-out `git pull --rebase origin main` would already ask for approval.

### Worked example

The agent runs `kubectl -n prod delete ns billing`.

1. The regex rule `\bkubectl\s+delete\b` does not match, because `-n prod` sits between `kubectl` and `delete`. The call passes.
2. With the default semantic layer the call is scored. The closest example is `kubectl delete ns prod --all --force`, and the score is 0.784. That is below 0.80, so the call still passes.
3. Add an example close to how your team writes the command, and the semantic layer asks:

```json
"semantic": {
  "examples": ["kubectl delete namespace"],
  "tools": { "Bash": { "role": "Operator" } }
}
```

Lowering `threshold` for `Bash`, for example to `0.75`, also makes it ask. Do it on the strength of your own benign samples: it moves the benign commands towards the line too. The request then carries the reason with the score, the path `$.command` and the closest example.

### Not a sandbox

As with a `when` rule, the semantic layer reduces approval noise for cooperative agents. It is not a security boundary. A model scores similarity, so a command the examples do not resemble, or one that is obfuscated, passes. Keep real isolation in the credentials and permissions of the account the commands run as.

## Grant scope

An approved request grants access for `grantMinutes`. By default (`"grantScope": "rule"`) the grant covers every call that matches the same rule in that time, whatever its arguments.

With `"grantScope": "call"` the grant is tied to the exact tool and arguments that were approved. The approver sees the arguments in the request, approves exactly those, and a retry of the same tool with the same arguments hits the grant. The arguments are compared after normalization: key order and whitespace do not matter. A call to another tool that the same pattern matches, such as `mcp__fs__delete_file` after an approved `mcp__fs__read_file` under `mcp__fs__*`, is a new request even with identical arguments.

Every argument field counts, not only the fields a `when` condition looks at. Some tools send fields that change from one attempt to the next: Claude Code's `Bash` sends a `description` and often a `timeout`, which a model tends to reword or adjust on a retry. A retry with any changed field starts a new request. Use `"call"` for tools whose arguments the agent repeats exactly, such as most MCP tools, and keep `"rule"` for `Bash`.

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
| Any of the above with `grantScope: "call"` | The name followed by `#` and 32 hex characters, the fingerprint of the tool name and the canonical arguments |

An existing config file keeps its policy names, so pending requests and active grants survive an upgrade. Turning an object into a one-element array keeps them too.

The receipt the CLI prints names the rule that matched, for example `Rule: approval:Bash[1]`.

## Notify on new requests

Set `notifyUrl` and the CLI POSTs a JSON body to it when a call creates an approval request. Approvers learn about the request without watching the terminal or the dashboard.

```json
{
  "backend": "sqlite",
  "databasePath": "/var/lib/ai-sentinel/approvals.db",
  "notifyUrl": "https://hooks.slack.com/services/T000/B000/XXXX",
  "dashboardUrl": "https://dash.example.com/ai-sentinel/",
  "tools": { "delete_database": { "role": "DBA" } }
}
```

The webhook belongs to the CLIs: `sentinel-hook`, `sentinel-copilot-hook` and `sentinel-mcp`. A host that calls `AddAISentinel` in code gets no notifier API.

### Keys

| Key | Type | Default | Notes |
|---|---|---|---|
| `notifyUrl` | string | none | Absolute `http` or `https` URL. |
| `notifyHeaders` | object | empty | Header name to string value. Needs `notifyUrl`. `Content-Type` and `Content-Length` are rejected, because the notifier sets them. |
| `notifyIncludeArgs` | bool | `false` | Adds `args` to the body. Needs `notifyUrl`. |
| `dashboardUrl` | string | none | Absolute `http` or `https` URL of your dashboard, including the path prefix, for example `https://dash.example.com/ai-sentinel/`. Valid on its own, but only the webhook reads it. |

`notifyHeaders` or `notifyIncludeArgs` without `notifyUrl` fails the load.

Header names are case-insensitive. Two names that differ only in case fail the load.

`${VAR}` is expanded in all four values, as described under [Environment-variable interpolation](#environment-variable-interpolation). An unset variable becomes an empty string, and the load fails in two cases:

- `notifyUrl` becomes empty, and the load fails with `notifyUrl is empty`. The message never quotes the value, because the value of a webhook URL is a secret.
- A header value is empty or only whitespace. `"Authorization": "${NTFY_TOKEN}"` with `NTFY_TOKEN` unset fails the load and names the header.

A value that is only partly empty is not caught. `"Bearer ${NTFY_TOKEN}"` with the variable unset expands to `"Bearer "`, which the loader accepts and sends. The loader does not trim. If the receiver answers `401`, check that the variable is set in the process that runs the hook.

### Payload

`POST notifyUrl` with `Content-Type: application/json`:

```json
{
  "text": "Approval needed: Bash for alice (approval:Bash). https://dash.example.com/ai-sentinel/approvals/req-1234",
  "requestId": "req-1234",
  "tool": "Bash",
  "callerId": "alice",
  "policy": "approval:Bash",
  "requestedAt": "2026-10-31T12:00:00+00:00",
  "approvalUrl": "sentinel://approve/req-1234",
  "dashboardUrl": "https://dash.example.com/ai-sentinel/",
  "args": { "command": "curl -H 'Authorization: [SECRET_1_k3f9x2]' https://api.example.com" }
}
```

| Field | Notes |
|---|---|
| `text` | One line for chat tools. With the `sqlite` backend and `dashboardUrl` set, the link at the end is the page of this request, `dashboardUrl` plus `approvals/{requestId}`, served by [`sentinel dashboard`](/docs/approvals/dashboard#the-cli-dashboard-as-an-approval-host). With another backend it is `dashboardUrl` as is when set, otherwise `approvalUrl` when that is an `http` or `https` URL, such as the Entra PIM portal URL. Otherwise there is no link. |
| `requestId`, `tool`, `callerId`, `policy`, `requestedAt` | The request, as the store holds it. `policy` is the [policy name](#policy-names). |
| `approvalUrl` | The URL the store reports for the request, sent as is. |
| `dashboardUrl` | The config value. Omitted when not set. |
| `reason` | Why approval is needed, for a [semantic](#what-the-approver-sees) request. Omitted for a rule-based one. |
| `args` | Only with `notifyIncludeArgs: true`. See [Arguments](#arguments). |

With `entra-pim`, `callerId` is the caller's Entra object id and `approvalUrl` is the PIM portal URL of the request. `dashboardUrl` is sent in its normalized form, so a bare host gains a trailing slash.

The per-request link needs `sentinel dashboard` running over the same approval config. With `entra-pim` the link stays the base URL, because approvers decide in the Azure portal.

The webhook fires once per request, when a call creates it. A later call that finds the request still pending sends nothing.

### Arguments

With `notifyIncludeArgs: true` the body carries the tool arguments, redacted. The notifier always scans them for credentials and PII, whatever other [redaction](/docs/redaction) settings the CLI has. Argument names stay. Values that match are replaced by placeholders such as `[SECRET_1_k3f9x2]`, and the original values never leave the process. Values that do not match are sent as they are, so keep this off if the arguments can hold sensitive text that no detector recognises.

### Slack

Use the Slack incoming webhook URL as `notifyUrl`. Slack reads `text` and ignores the other fields.

```json
{
  "notifyUrl": "https://hooks.slack.com/services/T000/B000/XXXX",
  "dashboardUrl": "https://dash.example.com"
}
```

### ntfy

```json
{
  "notifyUrl": "https://ntfy.sh/my-approvals",
  "notifyHeaders": { "Authorization": "Bearer ${NTFY_TOKEN}" }
}
```

ntfy shows the raw JSON body as the message text. It does not read `text`. Use it as is, or put a small relay in front that picks the fields you want.

### When the POST fails

The POST has a fixed 3 second timeout and is not retried. The response body is not read. A non-2xx status, a network error or the timeout is logged as a warning that names the endpoint's host, not the endpoint, and the request id. The path and query are left out because they often carry the secret, and so are the header values and the payload. Redirects are not followed: a 3xx counts as a failure. A webhook failure never changes the approval or its outcome. Each CLI then behaves as described in [Per-CLI behavior on `RequireApproval`](#per-cli-behavior-on-requireapproval).

`sentinel-mcp` writes the warning to stderr. The two hooks write it to stderr only when stderr does not carry the block reason, because the agent reads that reason. A blocking `PreToolUse`, the usual case for a new request, therefore shows the warning only with [`SENTINEL_HOOK_VERBOSE=1`](/docs/integrations/claude-code). Set it while you set up the webhook.

The POST is awaited, so it adds up to 3 seconds to the call that creates a request, in all three CLIs. The two hooks send it before they print the receipt.

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
- An empty array under a tool key, an empty `when`, an invalid path or regex, or an unknown `grantScope` → fail.
- An entry without `when` that is not last in its array → fail.
- A tool entry key that is a known key spelled differently, such as `grant_scope`, `grantscope` or `When` → fail, naming the key and the expected spelling. Other unknown keys, such as `description`, are ignored.
- A duplicate key inside `tools`, inside a tool entry or inside a `when` → fail.
- `grantScope: "call"` with `backend=entra-pim` → fail.
- A `semantic` block with `backend=entra-pim` or `backend=none`, without `tools`, with an empty `tools`, with `replaceExamples: true` and no `examples`, with a blank example, a `threshold` outside (0, 1], a bad `paths` entry, a `grantScope` or another unknown key → fail. See [Semantic approvals](#semantic-approvals).
- `notifyUrl` or `dashboardUrl` that is not an absolute `http` or `https` URL → fail.
- `notifyHeaders` or `notifyIncludeArgs` without `notifyUrl` → fail.
- A `notifyHeaders` value that is not a string, is empty after expansion, or is not a valid header, a duplicate name in any case, or `Content-Type` or `Content-Length` → fail.

Validation failures print to stderr and exit `1`, with one exception: on `PreToolUse`, `sentinel-hook` and `sentinel-copilot-hook` block the tool call with exit `2` and `Sentinel internal error: approval config '<path>' could not be loaded: <message>`, and record an audit entry with the code `internal_error`. A broken file must not turn off every approval rule. Fix the file, or unset `SENTINEL_APPROVAL_CONFIG`, to unblock tool calls. See [Claude Code → When the hook itself fails](/docs/integrations/claude-code#when-the-hook-itself-fails). Successful load is silent.

## See also

- [In-memory backend](/docs/approvals/in-memory) — the default.
- [SQLite backend](/docs/approvals/sqlite) — persistent, single-host.
- [Entra PIM backend](/docs/approvals/entra-pim) — enterprise.
