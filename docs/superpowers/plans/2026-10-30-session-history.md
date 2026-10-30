# Session History and Drift Escalation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fill `SentinelContext.History` with the session's recent audit entries on every scan, and escalate OPS-13 and HAL-07 one severity level when the same detector already flagged the session at least twice.

**Architecture:** An internal `SessionHistory` helper reads bounded, re-filtered entries from `IAuditStore`. `SentinelPipeline.ScanAsync` fills `History` with it and hands the context an internal earlier-hits lookup. `DetectionPipeline.RunAsync` escalates detectors marked with the internal `ISessionEscalatingDetector` through that lookup, before the semantic cap.

**Tech Stack:** .NET 10, C#, xUnit, Microsoft.Extensions.AI, SQLite via AI.Sentinel.Sqlite.

**Spec:** `docs/superpowers/specs/2026-10-30-session-history-design.md`

## Global Constraints

- History bounds: newest 50 entries, no older than 24 hours, ordered oldest first. Internal constants, no new public API.
- Earlier-hits lookup: same session, same `DetectorId`, last 24 hours, `PageSize = 2`, severity above `None`.
- Escalation threshold: 2 or more earlier hits → exactly one level up, never more. A clean result is never escalated.
- Escalation runs after the first `ApplySeverityClamp` and before `ProposedSeverities` and `ApplySemanticCap`, followed by a second `ApplySeverityClamp`.
- Reason suffix, verbatim: `; repeated in earlier scans of this session`.
- A failed store read never fails a scan: empty History or zero hits, plus a message to `SentinelOptions.OnDetectorFailure`. A cancelled caller token still cancels.
- Every result read from a store is re-filtered by session, age, and detector id where applicable. A custom store may ignore `AuditQuery` filters.
- Commits: one per task, conventional commits, no Claude trailer, no session links, no nested parentheses in commit bodies.

## Review Focus

- A custom store that returns the entries oldest first despite `Reverse = true`: History must still be the newest 50, oldest first. Covered in Task 2, `ReadAsync_StoreIgnoresReverse_KeepsNewest50`.
- An entry whose timestamp lies in the future, from clock skew between hook processes: it counts as recent and does not throw. Covered in Task 2, `ReadAsync_FutureTimestamp_IsKept`.
- An entry with `SessionId` null in the store: it never reaches History. Covered in Task 2 by the ignoring-store test.
- A `SeverityCap` of Low on OPS-13: escalation must not lift it to Medium. Covered in Task 4, `Escalation_RespectsSeverityCap`.
- A Critical result: escalation has no level above Critical and must keep it Critical. Covered in Task 4, `Escalation_CriticalStaysCritical`.

---

### Task 1: Ring buffer query filters in place

**Files:**
- Modify: `src/AI.Sentinel/Audit/RingBufferAuditStore.cs`, `QueryAsync`, about lines 30-65
- Test: `tests/AI.Sentinel.Tests/Audit/RingBufferAuditStoreTests.cs`

**Interfaces:**
- Produces: no signature change. `QueryAsync` returns the same entries in the same order as before.

- [ ] **Step 1: Write the failing tests.** Add `Query_SessionFilterOnFullBuffer_ReturnsNewestMatchesOnly`. Fill a `RingBufferAuditStore(1_000)` with 1,000 entries, every 100th for session `"s"`, the rest for `"other"`. Query `{ SessionId = "s", Reverse = true, PageSize = 3 }` and assert the three newest `"s"` entries, newest first. Add `Query_ForwardWithPageSize_ReturnsOldestMatches`, the same in forward order. Add `Query_WrappedBuffer_KeepsOrder`: capacity 5, 8 appends, forward query returns entries 4-8 in order. These may pass already; they pin the semantics before the rewrite.
- [ ] **Step 2: Run them.** `dotnet test tests/AI.Sentinel.Tests --filter "FullyQualifiedName~RingBufferAuditStoreTests"`. Expected: PASS, since they pin existing behaviour.
- [ ] **Step 3: Rewrite `QueryAsync`.** Under `_lock`, walk the buffer by index in the requested direction, apply the existing filters, and add matches to a `List<AuditEntry>` until `PageSize` is reached. Release the lock, then yield. Drop `_buffer.ToArray()` and `Array.Reverse`. Keep the cancellation check per yielded entry. Read the buffer's own structure first; if it is a `Queue<T>` or a circular array, index it without copying.
- [ ] **Step 4: Run all ring buffer and audit tests.** `dotnet test tests/AI.Sentinel.Tests --filter "FullyQualifiedName~Audit"`. Expected: PASS, with no existing test changed.
- [ ] **Step 5: Check SQLite.** Confirm `SqliteAuditStore.QueryAsync` already emits `ORDER BY sequence DESC LIMIT $limit` with a `session_id` predicate, at `SqliteAuditStore.cs:327-350`. No change expected.
- [ ] **Step 6: Commit.** `perf(audit): filter ring buffer queries in place instead of copying the buffer`

### Task 2: SessionHistory reader

**Files:**
- Create: `src/AI.Sentinel/Audit/SessionHistory.cs`
- Test: `tests/AI.Sentinel.Tests/Audit/SessionHistoryTests.cs`

**Interfaces:**
- Produces, all `internal static` in `AI.Sentinel.Audit.SessionHistory`:
  - `const int MaxEntries = 50;`
  - `static readonly TimeSpan MaxAge = TimeSpan.FromHours(24);`
  - `const int EscalationThreshold = 2;`
  - `ValueTask<IReadOnlyList<AuditEntry>> ReadAsync(IAuditStore store, string sessionId, DateTimeOffset now, Action<string>? onFailure, CancellationToken ct)`
  - `ValueTask<int> CountEarlierHitsAsync(IAuditStore store, string sessionId, string detectorId, DateTimeOffset now, Action<string>? onFailure, CancellationToken ct)`. It returns at most `EscalationThreshold`.

- [ ] **Step 1: Write the failing tests.** Use a `FakeStore : IAuditStore` that returns a fixed list and ignores the query, and a `ThrowingStore`.
  - `ReadAsync_ReturnsOnlyThisSession_OldestFirst`: entries from `"s"`, `"other"` and `SessionId = null`; result is only `"s"`, ascending by `Timestamp`.
  - `ReadAsync_DropsEntriesOlderThan24Hours`: an entry at `now - 25h` is absent and one at `now - 23h` is present.
  - `ReadAsync_StoreIgnoresReverse_KeepsNewest50`: 60 matching entries returned oldest first; the result holds exactly the newest 50, oldest first.
  - `ReadAsync_FutureTimestamp_IsKept`: an entry at `now + 5min` is present.
  - `ReadAsync_StoreThrows_ReturnsEmptyAndReports`: result empty; `onFailure` received one message containing the session id.
  - `ReadAsync_CancelledToken_Throws`: `ThrowingStore` throws `OperationCanceledException` on a cancelled token, and `ReadAsync` rethrows it.
  - `CountEarlierHits_CountsOnlyThisDetectorAndSession`: entries of OPS-13 in `"s"`, OPS-13 in `"other"`, SEC-01 in `"s"`, and OPS-13 with `Severity.None`; count is 1.
  - `CountEarlierHits_StoreThrows_ReturnsZeroAndReports`.
- [ ] **Step 2: Run them.** `dotnet test tests/AI.Sentinel.Tests --filter "FullyQualifiedName~SessionHistoryTests"`. Expected: FAIL, `SessionHistory` does not exist.
- [ ] **Step 3: Implement `SessionHistory`.**
  - `ReadAsync` queries `{ SessionId, Reverse = true, PageSize = MaxEntries, From = now - MaxAge }`. It keeps entries with an ordinal-equal `SessionId` and `Timestamp >= now - MaxAge`, sorts by `Timestamp` descending, takes `MaxEntries`, then reverses.
  - `CountEarlierHitsAsync` queries `{ SessionId, DetectorId, Reverse = true, PageSize = EscalationThreshold, From = now - MaxAge }` and counts entries passing the session, detector, age and `Severity > None` checks, capped at the threshold.
  - Both catch `Exception ex when ex is not OperationCanceledException || !ct.IsCancellationRequested`. They report `$"AI.Sentinel: the audit history of session {sessionId} could not be read ({ex.GetType().Name}: {ex.Message}); this scan runs without it."` and return empty or 0.
- [ ] **Step 4: Run them.** Same command. Expected: PASS.
- [ ] **Step 5: Commit.** `feat(audit): read a bounded, re-filtered session history from the audit store`

### Task 3: SentinelPipeline fills History and provides the lookup

**Files:**
- Modify: `src/AI.Sentinel/Detection/SentinelContext.cs`: add the internal lookup property
- Modify: `src/AI.Sentinel/SentinelPipeline.cs`: keep the `TimeProvider` in a field, `ScanAsync` around line 822, `BuildContext` around line 892
- Test: `tests/AI.Sentinel.Tests/SentinelPipelineHistoryTests.cs`

**Interfaces:**
- Consumes: `SessionHistory.ReadAsync`, `SessionHistory.CountEarlierHitsAsync` from Task 2.
- Produces: `internal Func<DetectorId, CancellationToken, ValueTask<int>>? EarlierHits { get; init; }` on `SentinelContext`. Null means no lookup, as in contexts built by the SDK builder or tests; then nothing escalates.

- [ ] **Step 1: Write the failing tests.** Follow `SentinelPipelineSessionIdTests`: an echo client, a `RingBufferAuditStore`, a `ChatOptions` with `sentinel.session_id`. Add a `CapturingDetector` that records `ctx.History` per call and returns Low.
  - `History_HoldsEarlierEntriesOfTheSession_OldestFirst`: two calls in session `"a"`. The second call's prompt scan sees the first call's entries in ascending timestamp order.
  - `History_ExcludesOtherSessions`: a call in `"b"` between them does not appear in `"a"`'s History.
  - `History_ResponseLegSeesPromptLegEntries`: in one call, the response scan's History contains the prompt scan's entry.
  - `History_StoreThrowsOnQuery_ScanStillReportsFindings`: a store wrapper that throws on `QueryAsync`; the call returns normally, the Low finding is audited, and `OnDetectorFailure` got the history message.
  - `EarlierHits_IsSetOnPipelineContexts`: `CapturingDetector` asserts `ctx.EarlierHits` is not null.
- [ ] **Step 2: Run them.** `dotnet test tests/AI.Sentinel.Tests --filter "FullyQualifiedName~SentinelPipelineHistoryTests"`. Expected: FAIL; History is empty and `EarlierHits` does not exist.
- [ ] **Step 3: Implement.**
  - In `ScanAsync`, before `BuildContext`, call `SessionHistory.ReadAsync(auditStore, sessionId.Value, _timeProvider.GetUtcNow(), options.OnDetectorFailure, ct)`.
  - Pass the result to `BuildContext` as a new `IReadOnlyList<AuditEntry> history` parameter, replacing both `[]`.
  - Set `EarlierHits = (id, t) => SessionHistory.CountEarlierHitsAsync(auditStore, sessionId.Value, id.Value, _timeProvider.GetUtcNow(), options.OnDetectorFailure, t)`.
  - Keep `SentinelContext`'s public surface unchanged otherwise.
- [ ] **Step 4: Run them, then the whole SentinelPipeline suite.** `dotnet test tests/AI.Sentinel.Tests --filter "FullyQualifiedName~SentinelPipeline"`. Expected: PASS.
- [ ] **Step 5: Commit.** `feat(pipeline): fill SentinelContext.History with the session's recent audit entries`

### Task 4: Drift escalation in DetectionPipeline

**Files:**
- Create: `src/AI.Sentinel/Detection/ISessionEscalatingDetector.cs`
- Modify: `src/AI.Sentinel/Detection/DetectionPipeline.cs`: `RunAsync` lines 102-158, `ApplySemanticCap` around line 610
- Modify: `src/AI.Sentinel/Detectors/Operational/PersonaDriftDetector.cs`, `src/AI.Sentinel/Detectors/Hallucination/IntraSessionContradictionDetector.cs`
- Test: `tests/AI.Sentinel.Tests/Detection/SessionEscalationTests.cs`

**Interfaces:**
- Consumes: `SentinelContext.EarlierHits` from Task 3, `SessionHistory.EscalationThreshold` from Task 2.
- Produces: `internal interface ISessionEscalatingDetector : IDetector;`, a marker with no members, plus a doc comment giving the rule.

- [ ] **Step 1: Write the failing tests.** Use a `FakeEscalatingDetector(string id, Severity s) : ISessionEscalatingDetector` and a plain `FakeDetector`. The context's `EarlierHits` returns a configurable count and records which ids it was asked about.
  - `Escalation_TwoEarlierHits_RaisesOneLevel`: Low becomes Medium, and the reason ends with `; repeated in earlier scans of this session`.
  - `Escalation_OneEarlierHit_NoChange`.
  - `Escalation_FiveEarlierHits_StillOneLevel`: Low becomes Medium.
  - `Escalation_CleanResult_StaysClean_AndNoLookup`: the lookup is never called.
  - `Escalation_UnmarkedDetector_NotEscalated_AndNoLookup`.
  - `Escalation_NullLookup_NoChange`.
  - `Escalation_RespectsSeverityCap`: configuration `SeverityCap = Low` keeps Low.
  - `Escalation_CriticalStaysCritical`.
  - `Escalation_SemanticMediumToHigh_CappedWithoutReviewer`: use a semantic test detector built the way the existing semantic-cap tests do, marked with the interface. Medium escalates to High and is capped back to Medium. The reason starts with `Semantic match — capped at Medium pending review` and ends with the suffix.
  - `Escalation_SemanticMediumToHigh_ConfirmingReviewerReachesHigh`: same, with a reviewer that confirms, built like the existing `Review` tests. The final severity is High.
  - `DriftDetectors_AreMarked`: `PersonaDriftDetector` and `IntraSessionContradictionDetector` implement `ISessionEscalatingDetector`. No other type in `OfficialDetectors` does.
- [ ] **Step 2: Run them.** `dotnet test tests/AI.Sentinel.Tests --filter "FullyQualifiedName~SessionEscalationTests"`. Expected: FAIL.
- [ ] **Step 3: Implement.**
  - In `RunAsync`, after the first `ApplySeverityClamp`, call `private async ValueTask<bool[]?> EscalateRepeatedAsync(SentinelContext ctx, DetectionResult[] results, CancellationToken ct)`.
  - For each index whose detector is `ISessionEscalatingDetector` and whose result is not clean, with `ctx.EarlierHits` set, await the lookup sequentially. Only drift hits reach it, at most two per scan.
  - At `>= SessionHistory.EscalationThreshold`, set `Severity = min(Severity + 1, Critical)` and append the suffix to `Reason`. Return a flag array, or null when nothing escalated.
  - Then call `ApplySeverityClamp(results)` again.
  - Pass the flags to `ApplySemanticCap`, which appends the suffix to its rewritten reason for a flagged index.
  - Mark the two detectors with the interface.
- [ ] **Step 4: Run the detection and review suites.** `dotnet test tests/AI.Sentinel.Tests --filter "FullyQualifiedName~Detection|FullyQualifiedName~Review"`. Expected: PASS.
- [ ] **Step 5: Commit.** `feat(detectors): escalate OPS-13 and HAL-07 when they repeat within a session`

### Task 5: Hook end-to-end test and docs

**Files:**
- Test: `tests/AI.Sentinel.Tests/ClaudeCode/HookCliAuditTests.cs`
- Modify: `website/docs/core-concepts/architecture.md:51`, the `History` bullet
- Modify: `website/docs/detectors/operational.md` and `website/docs/detectors/hallucination.md`, the OPS-13 and HAL-07 sections

**Interfaces:**
- Consumes: everything above, through `Program.RunAsync` of the Claude Code CLI.

- [ ] **Step 1: Write the test.** Add `RepeatedPersonaDrift_EscalatesOnTheThirdPrompt` to `HookCliAuditTests`, using `HookAuditTestSupport` and `ExactMatchEmbeddingGenerator` as the class already does. Run three `user-prompt-submit` events with `session_id` `"drift"` and the prompt `My tone and style have changed from earlier in this conversation`, an OPS-13 Low example. Read the SQLite entries for OPS-13: the first two are Low, the third is Medium with the suffix in its summary. If the exact-match generator scores that prompt in another bucket, assert "third is one level above the first" instead.
- [ ] **Step 2: Run it.** `dotnet test tests/AI.Sentinel.Tests --filter "FullyQualifiedName~HookCliAuditTests"`. Expected: PASS.
- [ ] **Step 3: Update the docs.**
  - **architecture.md:** `History` holds the session's earlier audit entries, the newest 50 from the last 24 hours, oldest first. Entries carry findings, not message text. Remove the #387 "reserved" wording.
  - **Detector pages:** OPS-13 and HAL-07 rise one level when the same detector already flagged the session in two earlier scans within 24 hours. The semantic cap and any configured cap still apply.
  - Run `dotnet test tests/AI.Sentinel.Tests --filter "FullyQualifiedName~DetectorDocumentationTests"`. Expected: PASS.
- [ ] **Step 4: Full run.** `dotnet test` on the solution. Expected: all PASS. On the VM, run the DLL with `-noclass "*DetectorRegistrationTrimTests"` if the AOT publish step is unavailable, per project memory.
- [ ] **Step 5: Commit.** `test(hooks): cover drift escalation across hook runs, document session history`
