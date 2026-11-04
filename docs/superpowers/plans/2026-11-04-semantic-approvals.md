# Semantic Approvals Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An opt-in semantic layer in the tool-call guard that asks for approval when a covered tool's arguments are close to a destructive-action example, and never removes an approval.

**Architecture:** A `SemanticApprovalMatcher` scores selected argument texts against example vectors through the existing `EmbeddingScope`/`ScanEmbedder` stack. `DefaultToolCallGuard` runs it as a final stage when the rules would otherwise allow, and evaluates a call-scoped `semantic:<key>#<fingerprint>` spec through the existing approval path. A new `Reason` travels with the request to stores, receipt, webhook and dashboard.

**Tech Stack:** C# / .NET (net8.0 + net10.0), Microsoft.Extensions.AI embeddings, xUnit, SQLite, ASP.NET Core dashboard.

**Spec:** `docs/superpowers/specs/2026-11-04-semantic-approvals-design.md`

## Global Constraints

- Target frameworks net8.0 and net10.0; every test runs on both.
- Binary compatible: new members on existing public types are init-only properties or new overloads; no changed signatures.
- AOT and trim safe: no reflection-based JSON; new JSON goes through the existing source-generated contexts.
- Policy name for a semantic approval: `semantic:<key>#<fingerprint>`, key = the `semantic.tools` key as written, fingerprint = `ArgumentFingerprint.Compute(toolName, args)`.
- Grant scope is always call. `semantic` with `backend: entra-pim` is a config error, and `GrantScope.Call` on an `IRoleActivationApprovalStore` throws at guard resolution, as #457 does.
- Default text paths: `Bash`, `bash`, `powershell` → `$.command`; every other tool → the compact arguments JSON.
- Embedding failure on a covered call → approval required, `Reason` starts with `Semantic check failed:`. Caller cancellation propagates.
- Reason copy: match → `Semantic match {score:0.00} ≥ {threshold:0.00} on {path}: "{example}"`; failure → `Semantic check failed: {kind}; approval required (fail closed)`; append ` (text truncated)` when any scored text was truncated. For the whole-JSON default, `{path}` is `$`.
- Commit messages: conventional commits, no nested parentheses in bodies, no Claude signature or session links.
- Before each push: `dotnet format whitespace --verify-no-changes`.
- Test runs use a filter; a full run AOT-publishes. Example: `dotnet test tests/AI.Sentinel.Tests --filter "FullyQualifiedName~SemanticApproval"`.

## Review Focus

1. **Embedding dimension mismatch** (generator swapped or misconfigured, call vector length ≠ example vector length): cosine returns 0 today, which would silently not flag. Expect: treated as an embedding failure → approval required. Test in Task 7.
2. **Very large arguments** (a `Write` tool with a 2 MB file body, covered via whole-JSON): expect truncation at `MaxScanBytes` on a UTF-8 boundary, one embedding request, reason notes truncation. Test in Task 6.
3. **Concurrent first calls** (ten hook calls before example vectors exist): expect one example-embedding run shared by all callers, as for detectors. Test in Task 1 via the extracted helper.
4. **Tool-name case across hosts** (Claude Code `Bash`, Copilot `bash`): pattern matching is ordinal; expect `"Bash"` in config not to cover Copilot's `bash`, and both defaults to pick `$.command`. Test in Task 6 and docs in Task 12.
5. **A `RequireToolPolicy` that passes on a covered tool**: a passing policy is not an approval, so the semantic stage still runs. Test in Task 8.

---

### Task 1: Extract the per-generator shared example-embedding task

**Files:**
- Create: `src/AI.Sentinel/Detection/GeneratorSharedTask.cs`
- Modify: `src/AI.Sentinel/Detection/SemanticDetectorBase.cs` (the `ExampleSlot`, `GetExampleVectorsAsync`, `RunEmbeddingAsync` block, ~lines 612–690; and `EmbedExamplesAsync`)
- Test: `tests/AI.Sentinel.Tests/Detection/GeneratorSharedTaskTests.cs`

**Interfaces:**
- Produces:
  - `internal sealed class GeneratorSharedTask<T> where T : class` with `Task<T> GetAsync(IEmbeddingGenerator<string, Embedding<float>> generator, Func<CancellationToken, Task<T>> factory, CancellationToken ct)` and `bool TryPeek(IEmbeddingGenerator<string, Embedding<float>> generator, [NotNullWhen(true)] out Task<T>? task)`. Semantics are exactly today's `GetExampleVectorsAsync` remarks: one shared task per generator instance in a `ConditionalWeakTable`, failed or cancelled tasks dropped, waiter-cancel does not touch the shared task, owner-cancel makes live waiters retry, a timeout-style `OperationCanceledException` on a live owner token faults all waiters.
  - `internal static Task<ReadOnlyMemory<float>[]> ExampleEmbedder.EmbedAsync(IEmbeddingGenerator<string, Embedding<float>> generator, IEmbeddingCache? exampleCache, string[] texts, CancellationToken ct)`, moved out of `SemanticDetectorBase.EmbedExamplesAsync` unchanged, in `src/AI.Sentinel/Detection/ExampleEmbedder.cs`. It must throw `InvalidOperationException` on a count mismatch, as today.

- [ ] **Step 1: Write failing tests** `GeneratorSharedTaskTests`: `ConcurrentCallers_ShareOneFactoryRun` (10 parallel `GetAsync` calls, factory gated by a `TaskCompletionSource`, assert factory invoked once, all get the same instance); `FailedTask_IsDroppedAndRetried` (first factory throws, second call invokes factory again); `WaiterCancellation_DoesNotCancelSharedTask`; `OwnerCancellation_LiveWaiterRetries`; `DifferentGenerators_GetSeparateTasks`.
- [ ] **Step 2: Run** `dotnet test tests/AI.Sentinel.Tests --filter "FullyQualifiedName~GeneratorSharedTaskTests"` → FAIL, type missing.
- [ ] **Step 3: Implement** both types by moving the existing code; `SemanticDetectorBase` keeps `GetExampleVectorsAsync`/`TryPeekExampleTask` signatures and delegates to a `GeneratorSharedTask<ExampleVectors>` field.
- [ ] **Step 4: Run** the new tests plus `--filter "FullyQualifiedName~Detection|FullyQualifiedName~Semantic"` → all PASS.
- [ ] **Step 5: Commit** `refactor(detection): share the per-generator example embedding task`.

### Task 2: `Reason` on approval requests, in-memory store, receipt and webhook

**Files:**
- Modify: `src/AI.Sentinel/Approvals/ApprovalContext.cs`, `src/AI.Sentinel/Approvals/PendingRequest.cs`, `src/AI.Sentinel/Authorization/AuthorizationDecision.cs` (`RequireApprovalDecision`), `src/AI.Sentinel/Approvals/InMemoryApprovalStore.cs`, `src/AI.Sentinel/Approvals/ApprovalReceipt.cs`, `src/AI.Sentinel/Approvals/Notifications/ApprovalNotification.cs`, `src/AI.Sentinel/Approvals/AuditingApprovalStore.cs`, `src/AI.Sentinel/Authorization/DefaultToolCallGuard.cs` (`EvaluateApprovalAsync`)
- Test: `tests/AI.Sentinel.Tests/Approvals/ApprovalReasonTests.cs`

**Interfaces:**
- Produces:
  - `public string? Reason { get; init; }` on `ApprovalContext`, `PendingRequest`, `AuthorizationDecision.RequireApprovalDecision`.
  - `EvaluateApprovalAsync(caller, toolName, args, spec, store, ct, string? reason = null)`: sets `ApprovalContext.Reason` and the decision's `Reason`.
  - `ApprovalReceipt.Format` adds `Reason: {reason}\n` after the `Rule:` line when non-null.
  - `ApprovalNotification` gains `string? Reason`, serialised as `reason`, omitted when null, through the existing source-gen context.
  - The request audit entry from `AuditingApprovalStore` includes the reason in its summary text when non-null.
- Reason is fixed at request creation: `EnsureRequestAsync` for an existing pending request returns the stored reason, not the new one.

- [ ] **Step 1: Write failing tests:** `InMemory_StoresReason_OnCreate`; `InMemory_ExistingPending_KeepsFirstReason`; `Receipt_IncludesReasonLine_WhenSet` (assert exact text `"Rule: semantic:Bash#abc\nReason: Semantic match 0.91 ≥ 0.80 on $.command: \"delete a namespace\"\n"` substring); `Receipt_NoReasonLine_WhenNull`; `Notification_SerialisesReason_AndOmitsWhenNull`; `Audit_RequestEntry_ContainsReason`.
- [ ] **Step 2: Run** `--filter "FullyQualifiedName~ApprovalReasonTests"` → FAIL.
- [ ] **Step 3: Implement** as listed.
- [ ] **Step 4: Run** the filter plus `FullyQualifiedName~Approval` → PASS.
- [ ] **Step 5: Commit** `feat(approvals): carry a reason with each approval request`.

### Task 3: SQLite store persists `Reason`

**Files:**
- Modify: `src/AI.Sentinel.Approvals.Sqlite/SqliteApprovalSchema.cs`, `src/AI.Sentinel.Approvals.Sqlite/SqliteApprovalStore.cs` (insert ~line 151, select ~line 278)
- Test: `tests/AI.Sentinel.Approvals.Sqlite.Tests/SqliteApprovalReasonTests.cs`

**Interfaces:**
- Consumes: `ApprovalContext.Reason`, `PendingRequest.Reason` (Task 2).
- Produces: schema `user_version = 2`; migration `if (current < 2) ALTER TABLE approval_requests ADD COLUMN reason TEXT; PRAGMA user_version = 2;`, run after the v1 block.

- [ ] **Step 1: Write failing tests:** `Reason_RoundTripsThroughListPending`; `V1Database_MigratesToV2_KeepingRows` (create a v1 file with the old DDL and one row, open the store, assert the row lists with `Reason == null` and `PRAGMA user_version` is 2); `NullReason_StoredAsNull`.
- [ ] **Step 2: Run** `dotnet test tests/AI.Sentinel.Approvals.Sqlite.Tests --filter "FullyQualifiedName~SqliteApprovalReasonTests"` → FAIL.
- [ ] **Step 3: Implement** the migration and column read/write.
- [ ] **Step 4: Run** the whole Sqlite test project → PASS.
- [ ] **Step 5: Commit** `feat(approvals): store the request reason in the SQLite approval store`.

### Task 4: Dashboard shows `Reason`

**Files:**
- Modify: `src/AI.Sentinel.AspNetCore/DashboardHandlers.cs` (~line 597, the request detail `<dl>`; and the pending list row if it shows justification)
- Test: the existing dashboard handler test file under `tests/AI.Sentinel.Tests/AspNetCore/` that covers the request page.

**Interfaces:**
- Consumes: `PendingRequest.Reason`.
- Produces: `<dt>Why approval is needed</dt><dd>{HtmlEncode(session.Redact(reason))}</dd>`, rendered before Justification, only when non-blank.

- [ ] **Step 1: Write failing tests:** `RequestPage_ShowsReason_HtmlEncoded` (reason containing `<script>` renders encoded); `RequestPage_NoReasonRow_WhenNull`.
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `--filter "FullyQualifiedName~AspNetCore"` → PASS.
- [ ] **Step 5: Commit** `feat(dashboard): show why an approval request was raised`.

### Task 5: In-process API for semantic approvals

**Files:**
- Create: `src/AI.Sentinel/Approvals/Semantic/SemanticApprovalSpec.cs`, `src/AI.Sentinel/Approvals/Semantic/SemanticApprovalSettings.cs`, `src/AI.Sentinel/Approvals/Semantic/SentinelOptionsSemanticApprovalExtensions.cs`
- Modify: `src/AI.Sentinel/SentinelOptions.cs` (internal storage), `src/AI.Sentinel/ServiceCollectionExtensions.cs:85` (auto-register `InMemoryApprovalStore` when semantic tools exist too)
- Test: `tests/AI.Sentinel.Tests/Approvals/Semantic/SemanticApprovalOptionsTests.cs`

**Interfaces:**
- Produces (public):
  - `public sealed class SemanticApprovalSpec` with `string BackendBinding { get; set; }` (required at registration), `TimeSpan GrantDuration` (default 15 min), `bool RequireJustification` (default true), `TimeSpan WaitTimeout` (default 5 min), `float? Threshold`, `SemanticApprovalSpec Paths(params string[] jsonPaths)`; bad paths throw `ArgumentException` from `Paths`, via `ArgumentPath.Parse`.
  - `public sealed class SemanticApprovalSettings` with `float? Threshold`, `bool ReplaceExamples`, `SemanticApprovalSettings AddExamples(params string[] examples)` (blank throws).
  - `public static SentinelOptions RequireSemanticApproval(this SentinelOptions opts, string toolPattern, Action<SemanticApprovalSpec> configure)`: duplicate pattern throws; missing `BackendBinding` throws; threshold outside `(0, 1]` throws.
  - `public static SentinelOptions ConfigureSemanticApprovals(this SentinelOptions opts, Action<SemanticApprovalSettings> configure)`.
- Produces (internal): `SentinelOptions.GetSemanticApprovals()` → `(SemanticApprovalSettings Settings, IReadOnlyList<(string Pattern, SemanticApprovalSpec Spec)> Tools)`.

- [ ] **Step 1: Write failing tests:** registration order kept; duplicate pattern throws; empty paths array throws; bad path throws with the path in the message; `ReplaceExamples` with no examples throws at guard build (assert in Task 8 instead; here assert the settings record it); `AddAISentinel` with only semantic tools registers `IApprovalStore`.
- [ ] **Step 2: Run** `--filter "FullyQualifiedName~SemanticApprovalOptionsTests"` → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(approvals): builder API for semantic approvals`.

### Task 6: Built-in examples and text selection

**Files:**
- Create: `src/AI.Sentinel/Approvals/Semantic/SemanticApprovalExamples.cs`, `src/AI.Sentinel/Approvals/Semantic/SemanticApprovalText.cs`
- Test: `tests/AI.Sentinel.Tests/Approvals/Semantic/SemanticApprovalTextTests.cs`

**Interfaces:**
- Produces:
  - `internal static class SemanticApprovalExamples { public static readonly string[] Default; public const float DefaultThreshold = 0.80f; }`, the threshold being a placeholder that Task 11 replaces. 20–40 examples covering the spec's categories: namespace/cluster deletion, `DROP`/`TRUNCATE`, `rm -rf`, force-push, mass purge/delete, cloud resource-group deletion, key/credential revocation, disk format/wipe, written as they appear in commands, HTTP calls and SQL.
  - `internal readonly record struct ScoredText(string Path, string Text, bool Truncated)`.
  - `internal static IReadOnlyList<ScoredText> SemanticApprovalText.Select(string toolName, JsonElement args, IReadOnlyList<ArgumentPath>? paths, int maxBytes)`. Rules: explicit paths, else the default paths for `Bash`/`bash`/`powershell`, else whole compact JSON with path `$`; values via `ArgumentPath.Resolve`, where a missing value or `null` yields no entry; non-object/array args yield their raw text with path `$`; blank and duplicate texts dropped; each truncated to `maxBytes` UTF-8 bytes on a char boundary.

- [ ] **Step 1: Write failing tests:** `Bash_DefaultsToCommand`; `CopilotBash_And_Powershell_DefaultToCommand`; `OtherTool_UsesCompactJson`; `ExplicitPaths_EachYieldOneText`; `MissingAndNullPaths_YieldNothing`; `StringArgs_YieldRawText`; `LargeText_TruncatedOnUtf8Boundary` (2 MB string with a 4-byte emoji straddling the cap; assert valid UTF-8, `Truncated == true`, length ≤ cap); `DefaultExamples_NonEmpty_NoBlanks_NoDuplicates`.
- [ ] **Step 2: Run** `--filter "FullyQualifiedName~SemanticApprovalTextTests"` → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(approvals): built-in destructive examples and argument text selection`.

### Task 7: `SemanticApprovalMatcher`

**Files:**
- Create: `src/AI.Sentinel/Approvals/Semantic/SemanticApprovalMatcher.cs`, `src/AI.Sentinel/Approvals/Semantic/SemanticMatch.cs`
- Test: `tests/AI.Sentinel.Tests/Approvals/Semantic/SemanticApprovalMatcherTests.cs`

**Interfaces:**
- Consumes: `GeneratorSharedTask<T>`, `ExampleEmbedder.EmbedAsync` (Task 1); `SemanticApprovalText.Select`, `SemanticApprovalExamples` (Task 6); `SemanticApprovalSettings`, `SemanticApprovalSpec` (Task 5); `EmbeddingScope`, `ScanEmbedder.EmbedAsync`, `SemanticDetectorBase.MaxSimilarity`.
- Produces:
  - `internal abstract record SemanticMatch(string Key, SemanticApprovalSpec Spec)` with subtypes `NotFlagged`, `Flagged(float Score, float Threshold, string Path, string Example, bool Truncated)`, `Failed(string Kind, bool Truncated)`; `string? Reason` property implementing the Global Constraints copy (null for `NotFlagged`).
  - `internal sealed class SemanticApprovalMatcher(EmbeddingScope scope, SemanticApprovalSettings settings, IReadOnlyList<(string Pattern, SemanticApprovalSpec Spec)> tools, int maxBytes)` with `bool Covers(string toolName, out string key, out SemanticApprovalSpec spec)` (first matching pattern, using the same matching as `ToolCallPolicyBinding.Matches`) and `ValueTask<SemanticMatch> MatchAsync(string toolName, JsonElement args, CancellationToken ct)`.
- Behaviour: no texts → `NotFlagged`. Any `ScanEmbeddings.FailedCount > 0`, example embedding failure, empty vector, or vector length ≠ example length → `Failed`. Kind is the exception type name, or `"dimension mismatch"`, or `"empty vector"`. `OperationCanceledException` when `ct.IsCancellationRequested` propagates. Score = max over texts of max similarity to the effective example set (`Default` + added, or added only when `ReplaceExamples`); `Example` is the best-matching example text; threshold = spec's ?? settings' ?? `DefaultThreshold`; flag when score ≥ threshold.

- [ ] **Step 1: Write failing tests** with `ExactMatchEmbeddingGenerator`: `VerbatimExample_Flagged_WithScoreAndExample`; `UnrelatedText_NotFlagged`; `ScoreEqualToThreshold_Flagged`; `ReplaceExamples_IgnoresDefaults`; `AddedExample_Matches`; `GeneratorThrows_Failed_WithKind`; `DimensionMismatch_Failed` (a generator returning length-3 vectors for calls and length-4 for examples); `EmptyVector_Failed`; `CallerCancelled_Throws`; `CallTextCached_SecondCallNoGeneratorRequest` (via `RecordingEmbeddingGenerator`); `Reason_Copy_MatchesSpec` (exact strings from Global Constraints, including ` (text truncated)`).
- [ ] **Step 2: Run** `--filter "FullyQualifiedName~SemanticApprovalMatcherTests"` → FAIL.
- [ ] **Step 3: Implement.** Add a `MaxSimilarityIndex` overload beside `MaxSimilarity` in `SemanticDetectorBase` that also returns the best reference index; `MaxSimilarity` delegates to it.
- [ ] **Step 4: Run** → PASS, plus `FullyQualifiedName~Semantic` → PASS.
- [ ] **Step 5: Commit** `feat(approvals): semantic matcher for tool call arguments`.

### Task 8: Guard final stage and DI wiring

**Files:**
- Modify: `src/AI.Sentinel/Authorization/DefaultToolCallGuard.cs`, `src/AI.Sentinel/ServiceCollectionExtensions.cs` (`BuildToolCallGuard` ~line 316, `RejectCallScopedGrantsOnRoleActivationStore`)
- Test: `tests/AI.Sentinel.Tests/Approvals/Semantic/DefaultToolCallGuardSemanticTests.cs`

**Interfaces:**
- Consumes: `SemanticApprovalMatcher`, `SemanticMatch` (Task 7); `EvaluateApprovalAsync(..., reason)` (Task 2).
- Produces: `DefaultToolCallGuard` constructor gains a trailing optional `SemanticApprovalMatcher? semantic = null`. `CanRefuse` is also true when `semantic` is non-null.
- Guard flow, per spec "Where it runs": ungoverned + `Deny` → deny, no semantic; slot decision → return it; track `ruleGrantActive` = some group selected a spec and its store state was `Active`; at the end, if `!ruleGrantActive && semantic?.Covers(...)`, then `MatchAsync`. `NotFlagged` → Allow. `Flagged`/`Failed` → spec `semantic:<key>#<fingerprint>` (`GrantScope.Call`, `BackendBinding`, `GrantDuration`, `RequireJustification`, `WaitTimeout` from the semantic spec) through `EvaluateApprovalAsync` with `match.Reason`; `Failed` also logs a warning naming the tool and kind.
- DI: build the matcher from `DefaultEmbeddingScope` (default pipeline) and `opts.GetSemanticApprovals()`, with `maxBytes = opts.MaxScanBytes`. No scope while semantic tools are configured → log one warning `"Semantic approvals are configured but no embedding generator is; the semantic layer is inert."` and pass `null`. `ReplaceExamples` with no examples → throw `InvalidOperationException` at resolution. Semantic tools with an `IRoleActivationApprovalStore` → throw, as the existing call-scope check does.

- [ ] **Step 1: Write failing tests:** `UncoveredTool_NoEmbeddingRequest`; `RuleRequiresApproval_SemanticSkipped`; `RuleGrantActive_SemanticSkipped`; `NoRuleMatched_Flagged_RequiresApproval_WithSemanticPolicyNameAndReason`; `UngovernedCoveredTool_UnderAllow_Flagged`; `UngovernedCoveredTool_UnderDeny_DeniedWithoutEmbedding`; `PassingToolPolicy_SemanticStillRuns`; `EmbeddingFails_RequiresApproval_WithFailureReason`; `CallerCancelled_Propagates`; `ApprovedSemanticGrant_SameArgsAllowed_DifferentArgsAskAgain`; `NoGenerator_Inert_LogsWarningOnce`; `EntraPimStore_WithSemanticTools_Throws`; `ReplaceExamplesWithoutExamples_Throws`.
- [ ] **Step 2: Run** `--filter "FullyQualifiedName~DefaultToolCallGuardSemanticTests"` → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** the filter plus `FullyQualifiedName~DefaultToolCallGuard|FullyQualifiedName~Authorization` → PASS.
- [ ] **Step 5: Commit** `feat(approvals): semantic approval stage in the tool-call guard`.

### Task 9: `semantic` block in the approval config file

**Files:**
- Create: `src/AI.Sentinel/Approvals/Configuration/SemanticApprovalConfig.cs`
- Modify: `src/AI.Sentinel/Approvals/Configuration/ApprovalConfig.cs` (`public SemanticApprovalConfig? Semantic { get; init; }`), `ApprovalConfigLoader.cs`, `ApprovalBackendSelector.cs` (`Configure`)
- Test: `tests/AI.Sentinel.Tests/Approvals/Configuration/SemanticApprovalConfigTests.cs`

**Interfaces:**
- Produces: `internal sealed record SemanticApprovalConfig(float? Threshold, IReadOnlyList<string> Examples, bool ReplaceExamples, IReadOnlyList<KeyValuePair<string, SemanticToolConfig>> Tools)` and `internal sealed record SemanticToolConfig(string Role, int? GrantMinutes, bool? RequireJustification, IReadOnlyList<string>? Paths, float? Threshold)`. Tools keep file order.
- Loader errors (`InvalidOperationException`, message naming `semantic`, the tool key and field): unknown keys in the block or a tool entry, including `grantScope`; `tools` missing or empty; missing `role`; empty `paths`; bad path; blank example; `replaceExamples: true` with no examples; threshold outside `(0, 1]`; `backend: entra-pim`; `backend: none`.
- `Configure` maps the block onto `ConfigureSemanticApprovals` + `RequireSemanticApproval`, with `grantMinutes ?? DefaultGrantMinutes` and `requireJustification ?? true`, as for rules.

- [ ] **Step 1: Write failing tests:** a full valid block round-trips; each error above; a config without `semantic` parses as before (`Semantic == null`); `Configure` registers tools in file order with the defaults applied.
- [ ] **Step 2: Run** `--filter "FullyQualifiedName~SemanticApprovalConfigTests"` → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `--filter "FullyQualifiedName~Approvals.Configuration"` → PASS.
- [ ] **Step 5: Commit** `feat(approvals): semantic block in the approval config file`.

### Task 10: CLIs end to end

**Files:**
- Modify, only where needed: `src/AI.Sentinel.ClaudeCode.Cli/Program.cs` (~line 415–427), `src/AI.Sentinel.Copilot.Cli/Program.cs` (~line 425), `src/AI.Sentinel.Mcp.Cli/ProxyCommand.cs` (~line 281–297). Make sure the embedding generator is set on the same options that `ApprovalBackendSelector.Configure` runs on, and that a config with only a `semantic` block still configures approvals.
- Test: the existing CLI test folders `tests/AI.Sentinel.Tests/ClaudeCode`, `Copilot`, `Mcp`.

**Interfaces:**
- Consumes: everything above. Tests inject `ExactMatchEmbeddingGenerator` through each CLI's existing `embeddingGenerator` parameter.

- [ ] **Step 1: Write failing tests:** Claude Code hook: a `Bash` call whose command is a verbatim default example, with a config holding only a `semantic` block → blocked with a receipt containing `Rule: semantic:Bash#` and `Reason: Semantic match`. The same call with a throwing generator → blocked with `Reason: Semantic check failed:`. Copilot hook: a `bash` tool call under `"semantic": { "tools": { "bash": … } }` → blocked. MCP proxy: an HTTP-shaped tool with `paths: ["$.method", "$.url"]` → approval required. A benign call → allowed in each.
- [ ] **Step 2: Run** `--filter "FullyQualifiedName~Semantic&(FullyQualifiedName~ClaudeCode|FullyQualifiedName~Copilot|FullyQualifiedName~Mcp)"` → FAIL.
- [ ] **Step 3: Fix the wiring** the tests expose.
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(cli): semantic approvals in the hook and proxy CLIs`.

### Task 11: Tune the default threshold in ComplianceEval

**Files:**
- Create: `tools/AI.Sentinel.ComplianceEval/approval-phrases.json` with `fit` and `heldOut` sections, each with `destructive` and `benign` arrays of tool-argument texts: commands, HTTP method + URL, SQL. Benign covers reads and lists, such as `kubectl get pods -n prod`, `SELECT * FROM orders LIMIT 10`, `git push origin feature`, `ls -la`, `GET /api/items/1`. Destructive paraphrases are not copies of the built-in examples. At least 30 per array.
- Create: `tools/AI.Sentinel.ComplianceEval/ApprovalEvaluation.cs`
- Modify: `tools/AI.Sentinel.ComplianceEval/Program.cs` (an `--approvals [path]` option that runs only this evaluation), `src/AI.Sentinel/Approvals/Semantic/SemanticApprovalExamples.cs` (`DefaultThreshold`)

**Interfaces:**
- Consumes: `SemanticApprovalExamples.Default`, `SemanticDetectorBase.MaxSimilarity` (internal; `AssemblyAttributes.cs` already grants ComplianceEval InternalsVisibleTo).
- Produces: a markdown table of score distributions, then the chosen threshold = the lowest value at which no **held-out** benign text scores ≥ it, rounded up to 0.01, then held-out destructive recall at that threshold. With `--tuning`, only fit data is scored, matching the tool's existing convention.

- [ ] **Step 1: Run** `dotnet run --project tools/AI.Sentinel.ComplianceEval -- --approvals --model all-MiniLM-L6-v2 --out /tmp/approvals.md` after implementing the option. Expected: table, threshold, recall.
- [ ] **Step 2:** If held-out recall is below 50%, adjust the built-in examples using fit data only (`--tuning`), then rerun on held-out. Record both runs.
- [ ] **Step 3:** Set `DefaultThreshold` to the chosen value; rerun `--filter "FullyQualifiedName~SemanticApproval"` → PASS.
- [ ] **Step 4: Commit** `feat(approvals): tune the default semantic approval threshold`. The commit body carries threshold, benign max and recall; the eval table goes in the PR body.

### Task 12: Docs

**Files:**
- Modify: `website/docs/approvals/cli-config.md`, the in-process approvals page under `website/docs/approvals/`, and the approval sections of the CLI READMEs if they list config keys.

- [ ] **Step 1: Write** the `semantic` block reference: fields table, default paths with the `Bash`/`bash` case note, fail-closed behaviour, call-scoped grants, the `Reason` shown to approvers, the "not a sandbox" warning, tuning with `--approvals`, and the worked `kubectl -n prod delete ns x` example where the regex rule misses and the semantic layer asks. Document `RequireSemanticApproval` / `ConfigureSemanticApprovals`.
- [ ] **Step 2: Build** the docs site the way `.github/workflows/docs.yml` does → no broken links.
- [ ] **Step 3: Commit** `docs(approvals): semantic approvals`.

### Finish

- [ ] Full test run with the AOT trim tests excluded per the project memory, on both TFMs; `dotnet format whitespace --verify-no-changes`; then superpowers:requesting-code-review, then a PR whose body includes the Task 11 eval table.
