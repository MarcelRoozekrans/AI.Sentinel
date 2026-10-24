# Approval rules that match tool arguments: implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Approval bindings carry optional `when` conditions on tool arguments, a tool can have an ordered list of such bindings, and a grant can be tied to the exact approved arguments.

**Architecture:** A small condition layer, `ArgumentPath` plus `ArgumentCondition`, lives under `src/AI.Sentinel/Approvals/Conditions/`. `ApprovalSpec` carries the conditions and a grant scope. `DefaultToolCallGuard` groups approval bindings by pattern and evaluates the first whose conditions hold. The config loader and `ApprovalBackendSelector` map the array and `when` form onto `RequireApproval`, so the CLIs and in-process users share one path.

**Tech Stack:** C#, net8.0/net9.0/net10.0, System.Text.Json `JsonElement`, `System.Text.RegularExpressions`, xUnit v3.

**Spec:** `docs/superpowers/specs/2026-10-24-approval-argument-rules-design.md`

## Global Constraints

- Branch `feat/approval-when-457`, from `origin/main` at 3.5.0. One commit per task, conventional-commit messages, **no nested parentheses in commit bodies**, end each with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`, no session links.
- Existing config files and existing `RequireApproval` code keep working, and keep the policy name `approval:<pattern>`.
- Regexes: `RegexOptions.CultureInvariant`, case-sensitive, `IsMatch` semantics, match timeout 100 ms, or `NonBacktracking` where the pattern allows it. A timeout fails closed.
- Test sources: write hidden characters as `\u` escapes, never raw.
- VM rules: never AOT-publish, no parallel heavy builds. `export DOTNET_ROOT=$HOME/.dotnet PATH=$HOME/.dotnet:$PATH`. Run tests as `dotnet build tests/AI.Sentinel.Tests -c Release` then `dotnet tests/AI.Sentinel.Tests/bin/Release/<tfm>/AI.Sentinel.Tests.dll -noclass "*DetectorRegistrationTrimTests"` for net8.0 and net10.0; filter with `-class "<FullName>"` while iterating. Formatting: `dotnet format whitespace AI.Sentinel.slnx --verify-no-changes`.

## Review Focus

1. **Arguments that are a JSON string or `Undefined`** (Copilot `GuardToolArgs` fallback, no args sent): a binding with `when` must require approval, never throw. Test in Task 3 and in Task 6 through the Copilot adapter.
2. **A narrow rule under `DefaultToolPolicy = Deny`:** a `Bash` call outside the rule is allowed, not denied. Test in Task 3.
3. **Call-scoped grant with reordered keys and extra whitespace:** same fingerprint; a changed value gives a different one. Test in Task 3.
4. **A config that turns a single object into a one-element array:** the policy name stays `approval:<pattern>`. Test in Task 4.
5. **A regex that times out on a huge argument:** the call requires approval and a warning is logged. Test in Task 3 with a catastrophic pattern that `NonBacktracking` rejects, so the timeout path runs; assert `RequireApproval` and one warning.

---

### Task 1: Argument paths and conditions

**Files:**
- Create: `src/AI.Sentinel/Approvals/Conditions/ArgumentPath.cs`
- Create: `src/AI.Sentinel/Approvals/Conditions/ArgumentCondition.cs`
- Test: `tests/AI.Sentinel.Tests/Approvals/Conditions/ArgumentPathTests.cs`, `ArgumentConditionTests.cs`

**Interfaces:**
- Produces:
  - `internal sealed class ArgumentPath { public static ArgumentPath Parse(string path); public string Text { get; } public bool TryGetMatchText(JsonElement args, out string text); }`. `Parse` throws `ArgumentException` whose message contains the path for bad syntax.
  - `internal enum ConditionResult { Holds, DoesNotHold, TimedOut }`
  - `internal sealed class ArgumentCondition { public ArgumentCondition(string jsonPath, string pattern); public ArgumentPath Path { get; } public string Pattern { get; } public ConditionResult Evaluate(JsonElement args); }`. The constructor throws `ArgumentException` naming the path or pattern on bad input.

- [ ] **Step 1: Write the failing tests**

`ArgumentPathTests`, a `[Theory]` per group:
- Accepted and resolved against `{"a":{"b c":[10,"x"]},"m":"GET"}`: `$.m` → `GET`; `$['a']['b c'][1]` → `x`; `$.a['b c'][0]` → `10`; `$.a` → `{"b c":[10,"x"]}` compact.
- Value kinds: `true` → `true`; a nested array → its compact raw text; JSON string `"aé"` → unescaped `aé`.
- Not resolved, `TryGetMatchText` false: missing name, index out of range, index into an object, name into an array, value `null`.
- Rejected by `Parse`: `""`, `m`, `$`, `$..m`, `$.*`, `$[-1]`, `$[?(@.a)]`, `$.a[0:2]`, `$['unterminated`.
- Never throws: `TryGetMatchText` on `default(JsonElement)` and on a string element returns false.

`ArgumentConditionTests`:
- `Evaluate_MatchingValue_Holds`: `new("$.method", "^(POST|DELETE)$")` on `{"method":"DELETE"}` → `Holds`; on `{"method":"GET"}` → `DoesNotHold`; on `{}` → `DoesNotHold`.
- `Evaluate_IsCaseSensitiveUnlessInline`: `^post$` on `POST` → `DoesNotHold`; `(?i)^post$` → `Holds`.
- `Ctor_InvalidRegex_Throws`: pattern `(` → `ArgumentException` whose message contains `(`.
- `Evaluate_Timeout_ReturnsTimedOut`: pattern `^(a+)+\1$`, which `NonBacktracking` rejects because of the backreference, on 50 000 `a` plus `!` → `TimedOut`.

- [ ] **Step 2: Run, expect compile failure**

- [ ] **Step 3: Implement `ArgumentPath` and `ArgumentCondition`**

`Parse` produces a list of segments, name or index. `TryGetMatchText` walks with `TryGetProperty` and bounds-checked `[i]`, guarding on `ValueKind` at every step. Compact raw text: re-serialise with a non-indented `Utf8JsonWriter` via `JsonElement.WriteTo`. `ArgumentCondition` tries `RegexOptions.CultureInvariant | RegexOptions.NonBacktracking` first, and falls back to `CultureInvariant` with `TimeSpan.FromMilliseconds(100)` when construction throws `NotSupportedException`; it catches `RegexMatchTimeoutException` into `TimedOut`.

- [ ] **Step 4: Run, expect pass**
- [ ] **Step 5: Commit** `feat(approvals): JSON path conditions on tool arguments`

### Task 2: `ApprovalSpec` conditions, grant scope and rule naming

**Files:**
- Create: `src/AI.Sentinel/Approvals/ApprovalGrantScope.cs`
- Modify: `src/AI.Sentinel/Approvals/ApprovalSpec.cs`, `src/AI.Sentinel/Approvals/SentinelOptionsApprovalExtensions.cs`
- Test: `tests/AI.Sentinel.Tests/Approvals/SentinelOptionsApprovalExtensionsTests.cs`

**Interfaces:**
- Consumes: `ArgumentCondition` from Task 1.
- Produces:
  - `public enum ApprovalGrantScope { Rule, Call }`
  - On `ApprovalSpec`: `public ApprovalSpec WhenArgument(string jsonPath, string pattern)`, which is chainable and appends; `public ApprovalGrantScope GrantScope { get; set; } = ApprovalGrantScope.Rule;`; `internal IReadOnlyList<ArgumentCondition> Conditions { get; }`.
  - `RequireApproval` naming: the first approval binding for a pattern defaults to `approval:<pattern>`; when `PolicyName` still equals that default after `configure`, later ones become `approval:<pattern>[1]`, `[2]`, and so on. Any duplicate approval `PolicyName` on the options throws `InvalidOperationException` naming it.

- [ ] **Step 1: Write the failing tests**
- `WhenArgument_AddsConditionsInOrder`: two calls → `Conditions` has both, in order, with the given paths.
- `WhenArgument_BadPath_Throws` and `WhenArgument_BadRegex_Throws`: `ArgumentException`.
- `RequireApproval_SamePatternTwice_NumbersLaterEntries`: three calls on `"Bash"` → names `approval:Bash`, `approval:Bash[1]`, `approval:Bash[2]`.
- `RequireApproval_ExplicitName_IsKept`: second call sets `PolicyName = "kubectl-delete"` → kept.
- `RequireApproval_DuplicateName_Throws`: two calls on different patterns both setting `PolicyName = "x"` → `InvalidOperationException` containing `x`.
- `GrantScope_DefaultsToRule`.

- [ ] **Step 2: Run, expect failure**
- [ ] **Step 3: Implement.** XML docs on the new public members, written in the style of the existing ones. Check that `PublicAPI` tracking files exist with `git ls-files | grep -i PublicAPI` and update them if present.
- [ ] **Step 4: Run, expect pass**
- [ ] **Step 5: Commit** `feat(approvals): ApprovalSpec.WhenArgument and GrantScope`

### Task 3: Guard groups, fail-closed evaluation and call-scoped grants

**Files:**
- Create: `src/AI.Sentinel/Approvals/Conditions/ArgumentFingerprint.cs`
- Modify: `src/AI.Sentinel/Authorization/DefaultToolCallGuard.cs`
- Test: `tests/AI.Sentinel.Tests/Approvals/DefaultToolCallGuardConditionTests.cs`, `tests/AI.Sentinel.Tests/Approvals/Conditions/ArgumentFingerprintTests.cs`

**Interfaces:**
- Consumes: `ApprovalSpec.Conditions`, `GrantScope`, `ConditionResult`.
- Produces: `internal static class ArgumentFingerprint { public static string Compute(JsonElement args); }`, which returns 16 lowercase hex characters. No public change to the guard.

**Rules the guard implements** (from the spec, "Matching in the guard"):
- A call is governed if any binding's pattern matches the tool name; `DefaultToolPolicy` applies only when none does.
- Approval bindings with the identical `Pattern` string form a group positioned at the first member's index. `RequireToolPolicy` bindings are never in a group.
- Within a group, the selected binding is the first with no conditions, or whose conditions all hold. A condition holds on `Holds` or `TimedOut`. When `args.ValueKind` is neither `Object` nor `Array`, a binding with conditions is selected as if they held. No selected binding means the group gives no decision.
- `TimedOut` logs `LogWarning` once per call per binding, naming the `PolicyName` and the path.
- `GrantScope.Call`: evaluate against a copy of the spec with `PolicyName = $"{spec.PolicyName}#{ArgumentFingerprint.Compute(args)}"`. That name flows into `EnsureRequestAsync`, `RequireApproval` and `Deny`.

- [ ] **Step 1: Write the failing tests**, using the `StubStore` pattern from `DefaultToolCallGuardApprovalTests`, plus a recording store that captures `spec.PolicyName`:
- `FirstMatchingEntryWins`: `Bash` entries `[0]` prod-delete and `[1]` any delete; a call with `kubectl delete ns prod` → store sees `approval:Bash` only; a call with `kubectl delete pod x` → `approval:Bash[1]` only.
- `NoEntryHolds_IsAllowed_UnderDenyDefault`: guard with `ToolPolicyDefault.Deny`, one `Bash` entry for `kubectl delete`, call with `ls` → `AllowDecision`, store not called.
- `GroupSitsAtFirstMemberSlot`: register approval `Bash[0]`, `RequireToolPolicy("Bash", "deny-all")`, approval `Bash[1]`; the store returns `Active`; a call matching only `[1]` → `DenyDecision` from `deny-all`, with the store called once for `approval:Bash[1]`.
- `StringArgs_FailClosed` and `UndefinedArgs_FailClosed`: entry with `when` → `RequireApprovalDecision`, no exception.
- `Timeout_FailsClosed_AndWarnsOnce`: Review Focus item 5, asserting one warning through a capturing `ILogger<DefaultToolCallGuard>`.
- `CallScope_NameCarriesFingerprint`: the store sees `approval:Bash#` followed by 16 hex characters, and the `RequireApprovalDecision.PolicyName` is the same string.
- `CallScope_OtherArgs_OtherRequest`: with `InMemoryApprovalStore`, approve the first request through `IApprovalAdmin`; the same args → `AllowDecision`; changed args → `RequireApprovalDecision` with a new request id.
- `RuleScope_GrantDoesNotCrossRules`: with `InMemoryApprovalStore`, approve `approval:Bash[1]`; a call matching `[0]` → still `RequireApproval`.
- `ArgumentFingerprintTests`: `{"b":1,"a":"x"}` and `{ "a" : "x", "b" : 1 }` → equal; `{"a":"y","b":1}` → different; a nested object with reordered keys → equal; `"é"` and `"é"` in source → equal; a hard-coded expected value for `{"a":1}` pins the result across target frameworks.

- [ ] **Step 2: Run, expect failure**
- [ ] **Step 3: Implement.** Precompute the groups in the constructor: an ordered list of evaluation slots, each either a policy binding or an approval group. `ArgumentFingerprint`: write the canonical form with `Utf8JsonWriter` and default options, recursing with object properties sorted by `StringComparer.Ordinal` and strings via `WriteStringValue(GetString())`, numbers via `WriteRawValue(GetRawText())`; then SHA-256 and take the first 8 bytes as lowercase hex.
- [ ] **Step 4: Run the new tests plus `DefaultToolCallGuardTests` and `DefaultToolCallGuardApprovalTests`, expect pass**
- [ ] **Step 5: Commit** `feat(approvals): the guard picks the first approval rule whose conditions hold`

### Task 4: Config file: arrays, `when` and `grantScope`

**Files:**
- Modify: `src/AI.Sentinel/Approvals/Configuration/ApprovalToolConfig.cs`, `ApprovalConfig.cs`, `ApprovalConfigLoader.cs`, `ApprovalBackendSelector.cs`
- Test: `tests/AI.Sentinel.Tests/Approvals/Configuration/ApprovalConfigLoaderTests.cs`, `ApprovalBackendSelectorTests.cs`

**Interfaces:**
- Consumes: `ApprovalSpec.WhenArgument`, `GrantScope`, and Task 2's naming.
- Produces: `ApprovalConfig.Tools` becomes `IReadOnlyDictionary<string, IReadOnlyList<ApprovalToolConfig>>`; `ApprovalToolConfig` gains `IReadOnlyList<KeyValuePair<string, string>> When` in file order, empty when absent, and `ApprovalGrantScope GrantScope`.

- [ ] **Step 1: Write the failing tests**

Loader: each error throws `InvalidOperationException` whose message names `tools.<key>[<i>]` and the offending path or value:
- Object value → list of one; array value → list in order; existing tests updated to `Tools[key][0]`.
- Empty array; an element that is not an object; `when` not an object; empty `when`; a `when` value that is not a string; a bad path; a bad regex; `grantScope` other than `rule` or `call`; `grantScope: "call"` with `backend: entra-pim`; an entry without `when` that is not last in its array.
- `${VAR}` expansion also applies inside `when` values, as it does today because it runs on the raw text.

Selector:
- `Configure_ArrayEntries_BecomeOneGroup`: `Bash` with two entries → two bindings named `approval:Bash` and `approval:Bash[1]`, with conditions and `BackendBinding` per entry.
- `Configure_ObjectToOneElementArray_KeepsName`: Review Focus item 4.
- `Configure_GrantScopeCall_IsCarried`.

- [ ] **Step 2: Run, expect failure**
- [ ] **Step 3: Implement.** Build each condition with `new ArgumentCondition(path, pattern)` at load so bad input fails there, wrapping the `ArgumentException` into the `InvalidOperationException` that carries the location; the selector then calls `WhenArgument`.
- [ ] **Step 4: Run, expect pass**
- [ ] **Step 5: Commit** `feat(approvals): approval config accepts rule arrays with when and grantScope`

### Task 5: Entra PIM rejects call-scoped grants

**Files:**
- Modify: `src/AI.Sentinel/ServiceCollectionExtensions.cs`, in `BuildToolCallGuard`, or wherever the inner store type is resolvable through `ApprovalStoreAuditing.InnerStoreKey`.
- Test: `tests/AI.Sentinel.Approvals.EntraPim.Tests/`, a new `GrantScopeTests.cs`.

**Interfaces:**
- Consumes: `ApprovalGrantScope.Call`.
- Produces: resolving `IToolCallGuard` throws `InvalidOperationException` containing `GrantScope.Call` and `Entra PIM` when the inner store is `EntraPimApprovalStore` and any binding has `GrantScope.Call`. Core must not reference the EntraPim package: detect it through a marker, such as an `internal interface IRoleActivationApprovalStore` in core implemented by `EntraPimApprovalStore` via `InternalsVisibleTo`, or a `bool SupportsCallScopedGrants` the builder chooses. It must not be a type-name string comparison.

- [ ] **Step 1: Failing test** registering the EntraPim store with a fake `IGraphRoleClient`, plus `RequireApproval("Bash", s => s.GrantScope = ApprovalGrantScope.Call)`, then resolving `IToolCallGuard` → throws. A control test with `GrantScope.Rule` resolves fine.
- [ ] **Step 2: Run, expect failure.** **Step 3: Implement.** **Step 4: Run, expect pass.**
- [ ] **Step 5: Commit** `feat(approvals): reject call-scoped grants on the Entra PIM store at startup`

### Task 6: End to end through the three hosts

**Files:**
- Test: `tests/AI.Sentinel.Tests/ClaudeCode/AuthorizationTests.cs`, `tests/AI.Sentinel.Tests/Copilot/AuthorizationTests.cs`, `tests/AI.Sentinel.Tests/Mcp/AuthorizationTests.cs`, `tests/AI.Sentinel.Tests/Mcp/McpCliTests.cs`

Build options with `ApprovalBackendSelector.Configure(opts, ApprovalConfigLoader.Parse(json))` and an `InMemoryApprovalStore`, and use each file's existing adapter or interceptor helper.

- [ ] **Step 1: Tests**
- Claude Code, `PreToolUse` `Bash`: `kubectl delete ns prod` → deny-with-receipt naming `approval:Bash`; `kubectl get pods` → allowed.
- Copilot: the same two calls, plus `toolArgs` as an unparseable string → receipt, which is the fail-closed path, not a crash.
- MCP: an `http_request` tool with `when: {"$.method": "^(POST|DELETE)$"}`; `DELETE` → JSON-RPC approval error; `GET` → forwarded.
- `McpCliTests`: a config file with an array value loads through `ProxyCommand.BuildAuthorizationStackAsync` with `configError == false`; a config with a bad regex → `configError == true` and stderr names the location.
- [ ] **Step 2: Run on net8.0 and net10.0, expect pass.** If one fails, fix the root cause in the owning code, not the test.
- [ ] **Step 3: Commit** `test(approvals): argument rules end to end through the hooks and the MCP proxy`

### Task 7: Docs

**Files:**
- Modify: `website/docs/approvals/cli-config.md`, the in-process approvals page (find it with `grep -rl "RequireApproval" website/docs`), and `README.md` if it shows the `tools` shape.

- [ ] **Step 1:** In `cli-config.md`, extend the per-tool table with `when` and `grantScope`, and add these sections:
  - "Several rules per tool", covering the array form and first match wins;
  - "Argument conditions", with the path syntax and the value table copied from the spec, missing means no match, and non-object arguments and a timeout fail closed;
  - "Grant scope", covering `rule`, `call`, and Entra PIM rejecting `call`;
  - "Not a sandbox", with a `Bash` example evaded by `k=kubectl; $k delete ns prod`.

  Use the issue's three tools as worked examples, and document the naming rule for policy names. In-process page: `WhenArgument` and `GrantScope` with a C# example.
- [ ] **Step 2:** `dotnet format whitespace AI.Sentinel.slnx --verify-no-changes`, and the full test run on net8.0 and net10.0 → all green.
- [ ] **Step 3: Commit** `docs(approvals): argument conditions, rule arrays and grant scope`

The PR body uses a `BEGIN_COMMIT_OVERRIDE` block with one `feat(approvals): ...` line for the feature. It also has a line noting the in-process change: two plain `RequireApproval` calls on one pattern now apply only the first, from spec "Matching in the guard".
