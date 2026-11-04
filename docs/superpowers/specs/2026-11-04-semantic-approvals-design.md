# Semantic approvals that can only add approvals: design

Issue: #477. Follow-up from the #457 design (`2026-10-24-approval-argument-rules-design.md`, non-goals). The maintainer made the decisions marked **(decided)** on 2026-11-04. Calls made by the designer are marked **(designer's call)**.

## Why

#457 gates destructive calls through generic tools with `when` regexes on the arguments. Regexes miss rephrased calls: `\bkubectl\s+delete\b` does not catch `kubectl -n prod delete ns x`, `k=kubectl; $k delete ...` or `sh -c "..."`. A semantic layer compares the call to examples of destructive actions and asks for approval when it is close to one, even when no rule matched.

## Goals

- **(decided)** The layer runs only for tools listed in a `semantic` block, not for every tool call.
- **(decided)** It can only add approvals. It never turns a rule's approval or a deny into an allow, so the deterministic rules stay the gate an integrator can read and predict.
- **(decided)** If the embedding request fails for a covered tool, the call needs approval (fail closed), and the approver is told the semantic check failed, not that an example matched.
- **(decided)** A semantic approval covers that exact call: grant scope `call`, fingerprinted as in #457.
- **(decided)** AI.Sentinel ships a built-in set of destructive-action examples with a threshold tuned in `tools/AI.Sentinel.ComplianceEval`. Config can add examples or replace the set.
- **(decided)** Per covered tool, an optional list of JSON paths (#457 path syntax) picks the text to embed. Built-in defaults exist for shell tools; other tools embed the compact arguments JSON. Each path is scored separately; the highest score counts.
- The approver sees which example matched and the score.
- Works in all three CLIs through `SENTINEL_APPROVAL_CONFIG`, and in-process through the builder.
- Without an embedding generator the layer is inert; approvals keep working offline.

## Non-goals

- Semantic matching on tools not listed in the block.
- Removing or relaxing approvals, or semantic allow-lists.
- Making `Bash` safe. Like `when`, this reduces misses on cooperative agents; it is not a sandbox. The docs say so.
- Semantic matching on `RequireToolPolicy` bindings.
- A fail-open switch. Consistent with #478 (hooks fail closed, no switch).

## Anti-goals

- A semantic failure that silently lets a covered call through.
- The semantic layer changing the outcome of a call it does not cover, or of a call a rule already decided.
- A semantic grant that covers a different call than the one approved.
- A second embedding request for text the pipeline or a previous call already embedded, where the cache could have served it.

## Approaches

1. **Final stage in `DefaultToolCallGuard` (chosen, decided).** The guard gets an optional internal `SemanticApprovalMatcher`. After the slots finish with Allow and no approval rule applied, it runs the matcher and reuses `EvaluateApprovalAsync` with a fingerprinted spec. The guard knows whether a rule or a grant decided the call, and the store, audit, receipt, webhook and dashboard paths are reused unchanged.
2. **Decorator around `IToolCallGuard`.** Cleaner separation, but the decorator sees only `Allow` and cannot tell "a rule's grant let this through" from "no rule matched", so it would ask again for calls an approver just granted. Rejected.
3. **Detector in the scan pipeline.** Reuses `SemanticDetectorBase` directly, but mixes scanning with authorization and does not run on the in-process `AuthorizationChatClient` path. Rejected.

## Design

### Config file

```json
{
  "backend": "sqlite",
  "tools": { "Bash": { "role": "ProdOps", "when": { "$.command": "\\bkubectl\\b[\\s\\S]*\\bdelete\\b" } } },
  "semantic": {
    "threshold": 0.80,
    "examples": ["decommission a tenant"],
    "replaceExamples": false,
    "tools": {
      "Bash": { "role": "Operator" },
      "mcp__api__http_request": { "role": "Operator", "paths": ["$.method", "$.url"], "grantMinutes": 30 }
    }
  }
}
```

Block fields:

| Field | Type | Default | Notes |
|---|---|---|---|
| `tools` | object | required | Keys are tool patterns, same syntax as `tools` keys (exact or `*` wildcard). Must not be empty. |
| `threshold` | number | built-in tuned value | Cosine similarity, `0 < t ≤ 1`. |
| `examples` | string[] | none | Added to the built-in set. Empty strings are a config error. |
| `replaceExamples` | bool | `false` | `true` uses only `examples`; then `examples` must not be empty. |

Per-tool fields: `role` (required), `grantMinutes` (default `defaultGrantMinutes`), `requireJustification` (as for rules; every other `ApprovalSpec` field, such as `WaitTimeout`, takes the same file defaults a rule entry gets), `paths` (string[], #457 path syntax, parsed at load; empty array is a config error), `threshold` (overrides the block's). `grantScope` is not accepted: it is always `call` **(decided)**, so `semantic` with `backend: entra-pim` is a config error, as #457 does for `grantScope: "call"`.

Bad config fails at load, naming the tool key and field.

### Which text is embedded

- With `paths`: the value at each path, using the #457 value table (string unescaped; number/bool raw token; object/array compact JSON; `null` or missing yields no text).
- Without `paths`: built-in defaults by tool name **(designer's call)**: `Bash` → `$.command`; the Copilot shell tool → its command field; the builder confirms the exact Copilot tool name and field. Any other tool: the whole compact arguments JSON.
- Arguments that are not a JSON object or array: the raw text of the element is embedded (fail closed: something is always scored).
- No text at all (every path missing or null): the call is not flagged. **(designer's call)** A call that does not carry the field cannot carry the destructive command in it; the whole-JSON fallback for such calls would mostly add noise. The builder check may revisit this.
- Each text is capped at `SentinelOptions.MaxScanBytes` (today a total scan budget; there is no per-text limit, and no new option is added). Longer text is truncated at a UTF-8 boundary and the truncation is noted in the reason. **(designer's call)**

### Matching

- Each text is embedded once and compared to every example by cosine similarity; the call's score is the maximum over texts and examples. Score ≥ threshold flags the call.
- Example embeddings are cached per generator, like semantic detectors since Wave 2 (`ExampleEmbeddingCache`). Call texts go through `SentinelOptions.EmbeddingCache`. **(designer's call)**
- The embed and cosine code behind `SemanticDetectorBase` is extracted into an internal shared helper that both use, rather than duplicated or subclassed; this is not a detector and has no severity buckets. Existing detector tests guard the extraction. **(designer's call)**
- `DefaultToolCallGuard` gains an optional matcher constructor parameter. `ServiceCollectionExtensions` builds it where the guard is built today (`new DefaultToolCallGuard(...)`, line ~339), from `SentinelOptions.EmbeddingGenerator`, `EmbeddingCache` and `ExampleEmbeddingCache`; the "no generator" warning is logged there.

### Where it runs in the guard

`DefaultToolCallGuard.AuthorizeAsync` today: governed check on the tool name, then slots in registration order, then `Allow`.

New, only when a matcher is configured and the tool name matches a `semantic.tools` key (first matching key in config order wins):

1. If the tool is not governed by any binding and `DefaultToolPolicy` is `Deny`, the call is denied as today. The semantic layer never runs on a call that is already denied. **(designer's call)**
2. Being listed under `semantic` does not make a tool governed. Under `Allow` an unbound covered tool goes to step 4; under `Deny` it is denied (step 1). **(designer's call)**
3. If the slots return a decision (approval needed, deny, or a policy decision), that decision stands; the semantic layer does not run.
4. If the slots end in `Allow`, or the tool is ungoverned under `Allow`, **and no approval rule's spec was selected for this call**, the matcher runs. `EvaluateGroupAsync` today returns `null` both when no member applies and when the selected rule's grant is active; the guard tracks the second case separately (any selected rule, any grant scope). One selected rule with an active grant suppresses the matcher for the whole call, even if a later group selected nothing. If an approval rule was selected and its grant was active, the call is allowed without a semantic check: the approver already approved a rule that covers it. **(designer's call, the reason approach 1 was chosen)**
5. Flagged, or embedding failed: evaluate a spec named `semantic:<key>#<fingerprint>` (key = the `semantic.tools` key, fingerprint = #457 `ArgumentFingerprint.Compute(toolName, args)`), with the tool's role, grant minutes and justification setting, through the existing `EvaluateApprovalAsync`. Not flagged: `Allow`.

A failed check and a match share the spec name: the approver approved those exact arguments, so a retry with the same arguments after the provider recovers is covered by that grant. **(designer's call)**

There is no new timeout setting: the provider's own timeout applies (30 s for the OpenAI-compatible client), inside the host's hook budget. **(designer's call)**

Embedding failure means: the generator throws, times out, returns the wrong count, or returns an empty vector. Cancellation of the caller's token is cancellation, not failure, as in Wave 2. The guard logs a warning naming the tool.

### What the approver sees

**(decided)** `ApprovalContext` and `PendingRequest` gain an optional public `string? Reason { get; init; }`: init-only, so the change stays binary compatible. The reason is set when the request is created; an existing pending request keeps its reason. Custom `IApprovalStore` implementations that do not store it drop it. A semantic request sets it to e.g. `Semantic match 0.87 ≥ 0.80 on $.command: "delete a Kubernetes namespace"`, or `Semantic check failed: <error kind>; approval required (fail closed)`. Rule-based requests leave it null.

The reason is stored with the request and shown on the dashboard request view, in the receipt and in the webhook payload. The SQLite store adds a nullable column with a migration; the in-memory store keeps it in memory; the Entra PIM store is excluded by config. The audit entry for the request carries it.

### In-process API

```csharp
opts.RequireSemanticApproval("Bash", role: "Operator", s => s.Paths("$.command"));
opts.ConfigureSemanticApprovals(s => { s.Threshold = 0.80f; s.AddExamples("decommission a tenant"); });
```

**(designer's call)** Exact names are left to the builder; the shape mirrors `RequireApproval`. `ApprovalBackendSelector.Configure` maps the `semantic` block onto these calls so CLIs and the builder share one implementation. The matcher uses `SentinelOptions.EmbeddingGenerator`. When the block is configured but no generator is, the guard logs one warning at resolution and the layer is inert.

### Latency on the hook path

One embedding request per covered call, at most one per distinct text; cache hits cost nothing. The request runs under the existing embedding provider timeout. A timeout is an embedding failure, so the call asks for approval.

### Built-in examples and threshold

A new example set of destructive actions, phrased the way they show up in tool arguments (commands, HTTP methods + URLs, SQL), for example: delete a Kubernetes namespace, drop a database table, `rm -rf` a directory, force-push over a branch, purge all records, truncate a table, delete a cloud resource group, revoke all keys. A held-out set of benign tool calls (reads, lists, `kubectl get`, `SELECT`) is added to ComplianceEval, and the default threshold is chosen there with the bundled MiniLM model, the same way #432 tuned SEC detectors. **(decided)** Target: the lowest threshold at which no held-out benign call is flagged; recall on held-out destructive paraphrases is reported alongside. Unit tests use a fake generator; only ComplianceEval uses the real model. The eval output and the chosen value go into the PR.

## Testing

TDD, on net8.0 and net10.0.

- Loader: block parsing, each config error, `entra-pim` rejection, existing config files without `semantic` unchanged.
- Text selection: paths, defaults per tool, non-object arguments, missing paths, truncation.
- Matcher: score at, above and below the threshold; example-set merge and replace; caching of example and call embeddings.
- Guard: runs only for covered tools; never runs after a rule decision or a deny; active rule grant skips it; ungoverned covered tool under `Allow` and `Deny`; embedding failure and timeout ask for approval with the failure reason; caller cancellation propagates; flagged call's grant covers the same arguments and not different ones; inert without a generator.
- Reason end to end: stored by SQLite and in-memory stores, shown on the dashboard, receipt and webhook.
- End to end through each CLI with a fake embedding generator: Claude Code hook with `Bash`, Copilot hook, MCP proxy.

## Docs

- `website/docs/approvals/cli-config.md`: the `semantic` block, paths and defaults, fail-closed behaviour, the "not a sandbox" warning, tuning the threshold with ComplianceEval.
- The in-process approvals page: the builder calls.
- The issue's `kubectl` example as a worked example: the rule misses `kubectl -n prod delete ns x`, the semantic layer asks.

## Left to the builder

- Builder method names and the matcher's internal shape.
- The exact built-in example wording, within the categories above.
- The Copilot shell tool's name and command field for the default path; the repo already lists Copilot tool names in `PlaceholderGuard.CopilotTools` / `CopilotVsCodeTools`.
- The SQLite migration mechanics, following the store's existing migrations.
