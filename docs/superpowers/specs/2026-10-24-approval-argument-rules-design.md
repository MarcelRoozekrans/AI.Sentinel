# Approval rules that match tool arguments: design

Issue: #457. Target: 3.6.0. The maintainer made three decisions on 2026-10-24, marked **(decided)** where they apply. Calls made by the designer are marked **(designer's call)**.

## Why

Teams building on AI.Sentinel reported that approval rules match on the tool name only. Many destructive operations go through generic tools, where the name cannot separate a harmless call from a dangerous one:

- a generic HTTP proxy tool, where `GET /items/1` and `DELETE /items/1` are the same tool;
- a generic "invoke action" tool, where reading a state and an irreversible action are the same tool;
- the Claude Code `Bash` tool, where `kubectl get pods` and `kubectl delete namespace prod` are the same tool.

A rule on such a tool demands approval for every read or for nothing. Both are wrong: the first trains approvers to click yes, the second leaves the dangerous call ungated.

## Goals

- **(decided)** A tool binding can carry an optional `when` block of conditions on the tool arguments. Each condition is a JSON path into the arguments and a regex. All conditions must hold.
- **(decided)** A tool can have several bindings: in the config file, the value under a tool key is either one object, as today, or an array of objects. The first entry whose `when` holds is the rule for the call.
- **(decided)** A grant covers every call that matches its rule for `grantMinutes`, as today. A rule can opt into `"grantScope": "call"`, which ties the grant to the exact arguments that were approved.
- The same rules work in all three CLIs, through `SENTINEL_APPROVAL_CONFIG`, and in the in-process `RequireApproval` builder.
- Existing config files and existing code keep working unchanged and keep their pending and active grants across the upgrade.

## Non-goals

- **(decided)** Semantic or embedding-based matching. A follow-up issue covers a semantic layer that can only *add* approvals, never remove one: a call that looks destructive asks for approval even when no rule matched. #457 ships deterministic rules only.
- `when` on `RequireToolPolicy` bindings. Policies already receive the arguments through `IToolCallContext` and can inspect them in code.
- Full JSONPath. No wildcards, filters, recursive descent or slices.
- Making `Bash` safe. A regex on a shell command can be evaded with quoting, aliases, variables or `sh -c`. The docs say so plainly: a `when` rule reduces approval noise on cooperative agents, it is not a sandbox.

## Anti-goals

- A rule that silently stops gating. A bad regex, a bad path or a regex timeout must never turn into "no approval needed" without a trace: bad config fails at load, a timeout fails closed.
- Adding a narrow `when` rule must not change how calls *outside* that rule are treated. In particular a narrow `Bash` rule must not start denying other `Bash` calls under `DefaultToolPolicy = Deny`.
- Approving one call must not quietly approve a different rule's calls.

## Design

### Config file

```json
"tools": {
  "delete_database": { "role": "DBA" },
  "mcp__api__http_request": {
    "role": "Operator",
    "grantScope": "call",
    "when": { "$.method": "^(POST|PUT|PATCH|DELETE)$" }
  },
  "Bash": [
    {
      "role": "ProdOps",
      "when": { "$.command": "\\bkubectl\\b[\\s\\S]*\\bdelete\\b[\\s\\S]*\\b(prod|production)\\b" }
    },
    { "role": "Operator", "when": { "$.command": "\\bkubectl\\b[\\s\\S]*\\bdelete\\b" } }
  ]
}
```

Per-entry fields, in addition to today's `role`, `grantMinutes` and `requireJustification`:

| Field | Type | Default | Notes |
|---|---|---|---|
| `when` | object | none | Keys are JSON paths, values are regexes. An empty object is a config error. No `when` means the entry matches every call to the tool. |
| `grantScope` | string | `"rule"` | `"rule"` or `"call"`. `"call"` with `backend: entra-pim` is a config error, because a PIM grant is a role activation and cannot be tied to arguments. |

An array must not be empty. An entry without `when` that is not the last entry of its array makes the entries after it unreachable; that is a config error.

### JSON paths

Supported syntax: `$` followed by any sequence of `.name`, `['name']` (for names with dots, spaces or quotes) and `[n]` (array index, non-negative). Anything else is a config error at load.

The value a regex sees:

| JSON value at the path | Matched text |
|---|---|
| string | the string value, unescaped |
| number, `true`, `false` | the raw JSON token, e.g. `42`, `true` |
| object or array | the compact raw JSON text |
| `null`, or the path does not exist | the condition does not hold |

So a condition never matches a field the call did not send, in arguments that are a JSON object or array.

**Arguments that are not a JSON object or array fail closed.** **(designer's call, from the anti-goal)** Hosts can hand the guard other shapes: the Copilot hook passes a raw string element when `toolArgs` is a string that does not parse as JSON, and other hosts can pass `default(JsonElement)`, kind `Undefined`, when no arguments were sent. The Copilot hook itself passes an empty JSON object when no arguments were sent, so such a call is structured arguments with no fields: a condition on a field does not hold. For such arguments every condition of a binding with a `when` counts as holding, so the call needs approval. Otherwise a `DELETE` rule would go ungated whenever a host sends unparsed arguments. Path evaluation never calls `GetProperty` on a non-object; it walks with `TryGetProperty` and bounds-checked indexing. **(designer's call)** The alternative, demanding approval when a field is missing, would make every optional field a source of approval noise. A rule that must gate calls lacking a field can say so with a separate entry that has no condition on that field.

### Regexes

- Compiled once at load with `RegexOptions.CultureInvariant`, and `RegexOptions.NonBacktracking` where the pattern allows it, otherwise with a match timeout of 100 ms. Case-sensitive; a pattern can start with `(?i)`.
- `Regex.IsMatch` semantics: unanchored unless the pattern anchors itself. The docs show `^...$` for exact values.
- `.` does not match a newline, and a command or file body can span lines, so multi-part examples join their parts with `[\s\S]*` rather than `.*`.
- An invalid regex is a config error at load, naming the tool key, entry index and path.
- A timeout at match time **fails closed**: the condition counts as holding, so the call needs approval, and the guard logs a warning naming the rule, once per call per rule.

### Matching in the guard

`ToolCallPolicyBinding` gains an optional condition set. `DefaultToolCallGuard.AuthorizeAsync` already receives `args`.

1. **Governed or not** is decided on the tool name alone, as today. If any binding's pattern matches the tool name, the call is governed and `DefaultToolPolicy` does not apply, even when no `when` holds. This is what keeps a narrow rule from denying other calls of the same tool.
2. **Rule groups.** Approval bindings that share the exact same pattern string form a group, in registration order. For each group, the first binding whose `when` holds, or that has no `when`, is evaluated; the rest of the group is skipped. If none holds, the group contributes no decision.
3. Groups, and policy bindings, are then evaluated in registration order as today: the first non-null decision wins, an active grant continues to the next. A group takes the registration slot of its first member. **(designer's call)** `RequireToolPolicy` bindings never join a group, even on the same pattern; they are evaluated in their own slot as today.

A config `tools` key holding an array becomes one group. A key holding a single object is a group of one, which is today's behaviour.

**(designer's call)** Step 2 changes one in-process edge case: two `RequireApproval` calls with the same pattern and no `when` used to demand both approvals; now only the first applies. The config file could never express this, because JSON keys are unique. The changelog mentions it.

### Policy names and grants

The store keys a request and its grant on `(caller, PolicyName)`.

- A single-object entry, and entry 0 of an array, keep today's name, `approval:<pattern>`. Pending and active grants survive the upgrade, and also survive turning an object into a one-element array. **(designer's call)**
- An array entry at index `i ≥ 1` gets `approval:<pattern>[i]`. Each rule is its own policy, so a grant for the `Operator` rule never covers the `ProdOps` rule.
- Approval policy names must be unique. A duplicate, from an explicit `PolicyName` or otherwise, throws at registration.
- **`grantScope: "call"`:** the guard evaluates against a copy of the spec whose name has an argument fingerprint appended: `approval:Bash#<fingerprint>`. The fingerprint is the first 32 hex characters, 128 bits, of the SHA-256 of the UTF-8 tool name, a 0x00 byte and the canonical arguments. The tool name is included so that a call-scoped grant under a wildcard rule such as `mcp__fs__*` never covers another tool called with the same arguments. Canonical arguments: object keys sorted ordinally, no insignificant whitespace, strings re-escaped consistently. Both stores already dedupe on `PolicyName`, so no schema change is needed. **(designer's call)** The fingerprinted name is the policy name everywhere downstream: in the `RequireApproval` and `Deny` decisions, the receipt, the audit entries and the dashboard. That way the approver can match a receipt to its request, and the hash prefix shows which rule it belongs to. Rows do not accumulate any faster than today, because every new request is already its own row. The approver approves exactly the arguments shown in `args_json`; a retry of the same tool with the same arguments hits the grant, a retry with any other arguments or another tool starts a new request. Every argument field counts toward the fingerprint, together with the tool name, including fields such as Claude Code `Bash`'s `description` and `timeout` that models often change on retry; a retry with any changed field starts a new request. The flagship `"call"` example is therefore an MCP tool with stable arguments, not `Bash`.

### In-process API

`ApprovalSpec` gains:

```csharp
public ApprovalSpec WhenArgument(string jsonPath, string pattern);   // repeatable, all must hold
public ApprovalGrantScope GrantScope { get; set; } = ApprovalGrantScope.Rule;   // Rule | Call
```

`RequireApproval(pattern, ...)` called again for a pattern that already has an approval binding adds the next entry of that pattern's group. When `PolicyName` still holds the default `approval:<pattern>` after `configure` runs, the second and later entries get `approval:<pattern>[i]`, numbered from 1, which matches the config file's naming. A caller who sets a name keeps it, and the uniqueness check above catches collisions. Path syntax and regex errors throw from `WhenArgument`, at configuration time.

`GrantScope.Call` combined with the Entra PIM store throws when the tool-call guard is first resolved, from the place where the registered store type is known. The check sees through AI.Sentinel's own auditing wrapper only; a custom decorator around `EntraPimApprovalStore` hides the store from it.

`ApprovalBackendSelector.Configure` maps config entries onto these calls, so the CLIs and the builder share one implementation.

### What the approver sees

Unchanged: `args_json` is already stored with the request and shown on the dashboard and in receipts. The receipt and the dashboard show the policy name, which now says which rule matched, e.g. `approval:Bash[1]`.

## Testing

TDD, on net8.0 and net10.0.

- Path parser: each supported form, each rejected form.
- Value extraction: each JSON kind, missing path, `null`; string and `Undefined` arguments fail closed.
- Loader: object and array values, empty array, empty `when`, unreachable entry, bad regex, bad path, `grantScope: "call"` with `entra-pim`, existing config files unchanged.
- Guard: first match wins within a group; a group sits at its first member's slot, with a `RequireToolPolicy` on the same pattern interleaved; no match in a group means governed with no decision, under both `DefaultToolPolicy` values; groups and policy bindings interleave in registration order; a regex timeout fails closed.
- Grants: an `Operator` grant does not satisfy the `ProdOps` rule; a call-scoped grant covers the same arguments with keys in another order and whitespace, and not different arguments; a single-object rule and array entry 0 keep the pre-upgrade policy name; a duplicate policy name throws.
- End to end through each CLI with a config file: the Claude Code hook with `Bash`, the Copilot hook, and the MCP proxy with an HTTP-shaped tool.

## Docs

- `website/docs/approvals/cli-config.md`: the array form, `when`, `grantScope`, the path syntax and value table, fail-closed on timeout, the "not a sandbox" warning with a `Bash` evasion example.
- The in-process approvals page: `WhenArgument` and `GrantScope`.
- The issue's three examples as worked examples.

## Left to the builder

- Type and file names, beyond the public API above.
- Where in `AddAISentinel` the Entra PIM check sits.
- Whether `NonBacktracking` is chosen per pattern or the timeout is used everywhere, provided matching cannot hang.
- The exact canonical JSON writer, provided it is deterministic across runs, processes and both target frameworks.
