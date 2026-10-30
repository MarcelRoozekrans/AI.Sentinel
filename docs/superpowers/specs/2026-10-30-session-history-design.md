# Session history and drift escalation (#387)

## Why

`SentinelContext.History` is documented as the session's earlier `AuditEntry` records, for detectors that span turns such as HAL-07 IntraSessionContradiction and OPS-13 PersonaDrift. The pipeline always passes an empty list: `SentinelPipeline.BuildContext` constructs the context with `[]`, and no detector reads `History`. Only the Detectors SDK's `SentinelContextBuilder` sets it, for tests.

Two facts shape what a filled `History` is good for:

- **An audit entry holds no message text.** It carries a detector id, severity, the reason summary, session id and source. A detector cannot find earlier figures or earlier persona statements in it.
- **In-process calls already carry the conversation.** `Messages` holds the caller's chat history, and `NewMessagesFrom` (#436) marks which messages are new. HAL-07 and OPS-13 are semantic detectors that score the new messages.

What `History` adds is what earlier turns were flagged for. A drift that shows up as a Low or Medium hit on several turns is invisible to any single scan. This matters most for the hook CLIs, where each invocation is a new process and the SQLite audit store is the only memory between turns.

## Goals

1. **The pipeline fills `History`** on every scan with the session's most recent audit entries, bounded by count and age.
2. **Drift escalation.** When OPS-13 or HAL-07 flags the current scan and the same detector already flagged this session at least twice within the bounds, its finding goes up one severity level.
3. **Existing guards still decide.** The configured Floor/Cap and the semantic cap at Medium still apply after escalation. Repetition alone never reaches High; only a reviewer verdict can, as today.
4. **Cheap reads.** Filling History costs one bounded store query per scan, plus one narrow query per drift hit. `RingBufferAuditStore.QueryAsync` stops copying the whole buffer to answer them.

## Non-goals

- Escalation for any detector other than OPS-13 and HAL-07. Marcel's decision: for most detectors a repeat is the same topic coming up again, not drift.
- A public per-detector setting for session escalation.
- Storing message text in audit entries.
- New-message scoping for the rule-based detectors: that is #439, PR #546.

## Anti-goals

- **Escalation that creates a finding.** A clean scan stays clean, whatever History holds. Escalation refines a finding the detector already made, the same rule as `StubDetector` documents.
- **A path past the reviewer.** Escalation must not lift a semantic result above the semantic cap without a reviewer verdict.
- **A failed history read that disables detection.** The detectors still run and report at their own severity.

## Approaches

- **A. Fill History before every scan, escalate on drift hits. Chosen.** `SentinelPipeline.ScanAsync` reads the session's recent entries before building the context, so custom detectors get a real History and the docs become true. When OPS-13 or HAL-07 flags a scan, a narrow lookup finds that detector's earlier hits. Cost: one store read per scan, so the ring buffer's query is fixed to filter in place.
- **B. Query only when a drift detector fires.** No read on clean scans, but History stays empty for custom detectors, so the docs caveat stays and #387 is half done. Rejected.
- **C. In-memory per-session counter.** Cheapest, but it forgets between hook invocations, the case that needs this most. Rejected.

Marcel picked A on 2026-10-30, with a failed read degrading to an empty History.

Counting the earlier hits from `ctx.History` itself was considered and rejected: History holds the 50 most recent entries of every detector, and until #546 lands the rule-based detectors repeat their findings every turn, so they can push the drift hits out of the window and escalation would silently stop firing. Marcel chose the narrow lookup on a hit instead of a larger window.

## Design

### Reading the history

All surfaces, in-process clients, `ScreenAsync`, the hook CLIs and the MCP proxy, scan through `SentinelPipeline.ScanAsync`. It reads the history once per scan, before `BuildContext`:

```
new AuditQuery { SessionId = sessionId.Value, Reverse = true, PageSize = 50, From = now - 24h }
```

- The bounds are 50 entries and 24 hours, as internal constants. *Builder's call, see below.*
- The pipeline does not trust the store to apply the filters: a custom `IAuditStore` may ignore them, as the `AuditQuery` docs allow. It drops entries of another session or older than the age bound, orders by timestamp and keeps the newest 50.
- The result is passed to `SentinelContext` as `History`, oldest first, so it reads like a transcript. *My call: the `History` docs say "previous records", and a chronological list is what a custom detector would expect.*
- The prompt leg's entries are written before the response leg scans, so the response leg's History includes them. That is intended: they are earlier findings in the same session.
- A call without a caller-supplied session id gets a fresh id, so its History holds at most its own prompt leg's entries. No special case.

**Failure.** Cancellation of the caller's token propagates as today. Any other exception from the store is caught: the scan proceeds with an empty History and the pipeline logs a warning naming the session. Detection is unaffected; only escalation is lost for that scan.

### The ring buffer query

`RingBufferAuditStore.QueryAsync` today copies the whole buffer, up to 10,000 entries, to an array on every call and then filters. With a read on every scan that is an 80 KB allocation per scan. The fix: under the lock, walk the buffer in the requested direction, apply the filters, and copy only the matches up to `PageSize`. The query semantics are unchanged; existing tests must pass as they are.

`SqliteAuditStore` already has an index on `session_id`. The builder checks that a `Reverse` query with `PageSize` becomes `ORDER BY … DESC LIMIT`, not a full read.

### Drift escalation

- **Which detectors.** OPS-13 and HAL-07 implement a new internal marker interface, `ISessionEscalatingDetector`. *My call: it keeps the knowledge on the detector, not as a list of ids in the pipeline, and adds no public API.*
- **The lookup.** For a marked detector whose current result is not clean, `DetectionPipeline` queries the audit store: this session, this `DetectorId`, the last 24 hours, newest first, `PageSize = 2`. It re-checks session, detector id and age on what comes back, for the same reason as above. It runs only on a drift hit, so a clean scan costs nothing extra. `DetectionPipeline` gets the store, or an internal lookup over it, when it is built; the builder picks the shape. A failed lookup degrades like a failed History read: no escalation, a warning, the normal finding.
- **What counts.** Entries with the same `DetectorId` and a severity above None. Redaction and disclosure entries carry other ids, so they never count.
- **The rule.** At two or more earlier hits, the current result goes up one level: Low to Medium, Medium to High, High to Critical. It is one step, however many earlier hits there are. *My call: predictable, and repeated pressure cannot climb several levels in one scan.*
- **No ratchet.** Escalation lifts the current scan's own severity. The earlier entries are only counted, never read for their severity, so an escalated entry written this turn does not raise the base next turn.
- **Where in `DetectionPipeline.RunAsync`.** After the first `ApplySeverityClamp` and before `ProposedSeverities` and `ApplySemanticCap`:
  1. escalate;
  2. re-apply the Floor/Cap clamp, the same re-clamp #515 added after review escalation, so a configured `SeverityCap` still holds;
  3. `ProposedSeverities` then records the escalated severity, so a reviewer that confirms can lift the result to it;
  4. `ApplySemanticCap` caps an embedding result above Medium back to Medium pending review, as today.
- **Reason.** An escalated result's reason gains "; repeated in earlier scans of this session". A scan writes at most one entry per detector, so the hits are earlier scans; the prompt and response legs of one call are two scans. When the semantic cap then rewrites the reason, the note is kept.
- **The semantic cap's floor rule is unchanged.** A configured `SeverityFloor` above Medium already raises the semantic cap level to the floor; escalation does not alter that.
- **Audit.** The escalated result is written to the audit store like any other, so it counts towards the next turn. One step per scan caps the effect.

### Overlap with PR #546

PR #546 (#439, not merged yet) also changes `SentinelContext` and the pipeline's context building. This work is designed against main. The overlap is a mechanical merge in `BuildContext` and `ScanAsync`; neither feature depends on the other. Until #546 lands, rule-based detectors rescan the whole conversation and repeat their findings every turn. Escalation is limited to two semantic detectors, which already score only new messages, so those repeats do not inflate its count.

## Tests

- Ring buffer: the query returns the same results as before for every filter and direction, including `PageSize` and `Reverse`, and a session-filtered query on a full buffer copies no more than the matches.
- Pipeline: `History` holds only the session's entries, at most 50, none older than 24 hours, oldest first; the response leg sees the prompt leg's entries; another session's entries never appear.
- Escalation: OPS-13 and HAL-07 go up one level after two earlier hits, even when more than 50 newer entries of other detectors sit between them and the current scan; one earlier hit does nothing; a clean result stays clean; another semantic detector with the same history does not escalate; a `SeverityCap` holds; without a reviewer a Medium-to-High escalation is capped back to Medium; with a confirming reviewer it reaches High.
- A store that ignores the filters: another session's entries and over-age entries never reach History or the count.
- No ratchet: three consecutive escalated scans stay one level above their own base severity.
- Failure: a store that throws on query gives an empty History and no escalation, a logged warning and the normal findings; a cancelled token still cancels.
- Hooks: the hook CLIs pass the host's session id on every event and write to the local SQLite store by default (`LocalAudit`), so this test is three hook runs in one session against one SQLite file; the third escalates.

## Docs

- `website/docs/core-concepts/architecture.md`: `History` is filled with the session's recent entries, with the bounds.
- The OPS-13 and HAL-07 detector docs: the escalation rule.
- Release type `feat:`, a minor version.

## Left to the builder

- Whether the 50-entry and 24-hour bounds are internal constants or also `SentinelOptions` settings. Default: internal constants, since Marcel did not ask for a setting and new public API needs his call.
- The logger used for the failed-read warning: whatever `SentinelPipeline` already logs through.
- Test names and fixtures.
