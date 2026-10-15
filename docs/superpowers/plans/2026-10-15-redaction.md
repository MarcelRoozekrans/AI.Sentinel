# Redaction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** PII and credentials in an in-process chat request reach the model as numbered placeholders. The user's reply and the tools get the real values back. The audit log records counts only, as informational entries.

**Architecture:**
- A per-call `RedactionSession` rewrites the outbound messages and records placeholder → value in memory only.
- The detection pipeline marks each detection with its effective action. A Redact that survives into a detection result means redaction was not possible, so it falls back to the severity action.
- Tool calls are intercepted at invocation time by wrapping `ChatOptions.Tools`, plus a response-side check for the other builder order. #359 (Task 1) shares this mechanism.

**Tech Stack:** .NET 8/9/10, Microsoft.Extensions.AI 10.11 (`DelegatingAIFunction`, `FunctionInvokingChatClient`), xunit.v3, `[GeneratedRegex]`.

**Spec:** `docs/superpowers/specs/2026-10-15-redaction-design.md`

## Global Constraints

- Branch each PR from a freshly fetched `origin/main`.
- **Task 1 is its own PR**, `fix(authorization): …`, closing #359.
- **Tasks 2–9 are one PR** closing #338. Exactly one commit in it is `feat!:`, with a `BREAKING CHANGE:` footer: Task 6, where the default turns on.
- Commit bodies must not contain nested parentheses, or release-please drops the commit.
- No original value may reach `AuditEntry`, a forwarder, an alert, a log message, an exception message or `DetectionResult.Reason`.
- Placeholder format is `[TYPE_n]`, where TYPE is upper case and n starts at 1 per type per session.
- Redaction audit entries use `PolicyCode = "REDACTED"` and `Severity = Severity.None`. Their summary looks like `Redacted 1 EMAIL, 1 IBAN`, with types in ordinal order.
- A fallback detection appends `; not redacted` to its audit summary.
- `SentinelOptions.RedactByDefault` defaults to `true`, and `SentinelOptions.RestoreRedactedValues` defaults to `true`.
- Analyzers run as errors. In particular ZA0601 forbids LINQ inside loops, which applies to tests too. Fix the code, never suppress.
- Run tests with `dotnet test tests/AI.Sentinel.Tests -- --filter-class "*<Name>*"`. Run the full `dotnet test` before each push.

## Review Focus

1. **A value split across two `TextContent` parts or two messages.** Each string is redacted on its own. That's acceptable, but it must never throw or corrupt offsets. Covered by a test in Task 5.
2. **Overlapping spans from two detectors.** For example, a credential regex and the phone regex both matching inside `api_key=0612345678`. The longest span wins, and the other is dropped, not nested. Covered by a test in Task 5.
3. **The model mangles a placeholder.** It returns `[email_1]`, `[EMAIL_1` or `EMAIL_1`. That text is left as-is, never partially restored. Covered by a test in Task 5.
4. **A caller reuses one `ChatOptions` instance across calls.** Tool wrapping must not mutate the caller's `ChatOptions` or its `Tools` list, and must not wrap a wrapper twice. Covered by a test in Task 6.
5. **A tool returns a non-string object,** such as a POCO or a `JsonElement`. Redaction of results covers strings and `JsonElement` string values. Other objects pass through unchanged, and the test documents that. Covered by a test in Task 6.

---

### Task 1: Authorize model-made tool calls at invocation time, #359 (own PR)

**Files:**
- Create: `src/AI.Sentinel/Tools/ToolInvocationInterception.cs`
- Modify: `src/AI.Sentinel/Authorization/AuthorizationChatClient.cs`
- Modify: `README.md`, at the builder example near line 320
- Test: `tests/AI.Sentinel.Tests/Authorization/Integration/ModelInitiatedToolCallTests.cs`

**Interfaces:**
- Produces: `internal static class ToolInvocationInterception` with:
  - `static ChatOptions? WrapTools(ChatOptions? options, ToolInterceptor interceptor)`. It returns a **clone** with every `AIFunction` in `Tools` wrapped, leaves other `AITool`s alone, and doesn't wrap an existing wrapper from the same interceptor again.
  - `delegate ValueTask<object?> ToolInterceptor(AIFunction inner, AIFunctionArguments args, CancellationToken ct)`.
  - Wrapping uses a private `sealed class InterceptingAIFunction : DelegatingAIFunction`.

- [ ] **Step 1: Write the failing tests.** Use a fake model whose first response is `FunctionCallContent("c1", "DeleteUser", {id: "42"})` and whose second response is the text "done". Use an `AIFunction` that increments `ran`. The caller is non-admin and `DeleteUser` is bound to `admin-only`. Write these tests:
  - `AuthorizationOutsideFunctionInvocation_DeniedCall_ToolNeverRuns`: build `UseToolCallAuthorization().UseFunctionInvocation()` and assert `ran == 0`.
  - `AuthorizationInsideFunctionInvocation_DeniedCall_ToolNeverRuns`: build `UseFunctionInvocation().UseToolCallAuthorization()` and assert `ran == 0` and that a `ToolCallAuthorizationException` reaches the caller.
  - `DeniedModelCall_WritesOneAuthzDenyEntry`: in both orders, the `RingBufferAuditStore` holds exactly one `AUTHZ-DENY` entry.
  - `AllowedModelCall_ToolRunsOnce`: with an admin caller, assert `ran == 1` in both orders.
- [ ] **Step 2: Run them.** Expected: the deny tests FAIL with `ran == 1`.
- [ ] **Step 3: Implement.** In `AuthorizationChatClient`:
  1. **Outside order:** wrap `options.Tools` with `ToolInvocationInterception.WrapTools`. The interceptor runs `AuthorizeFunctionCallAsync` on a `FunctionCallContent` rebuilt from the function name and arguments, then invokes `inner`.
  2. **Inside order:** after the inner response returns, and before returning it, run `AuthorizeFunctionCallsAsync` over the response messages. For streaming, check each update's `FunctionCallContent` before yielding it.
  3. Keep today's check of incoming messages.

  **Check what `FunctionInvokingChatClient` does when a wrapped function throws.** It may report the error to the model instead of rethrowing. Whichever it does, rename the outside-order test after what it asserts: either the exception reaches the caller, or the model gets a denial result. Document that behaviour in the README.
- [ ] **Step 4: Run** `--filter-class "*ModelInitiatedToolCallTests*"` and the existing `*InProcessAuthorizationTests*`. Expected: all PASS.
- [ ] **Step 5: Fix the README example.** Explain that authorization works in either order, and show the recommended order.
- [ ] **Step 6: Commit** with `fix(authorization): stop a denied tool call that the model makes from running`, closing #359. Run the full suite, push, and open the PR.

---

### Task 2: Redact action, per-detector action and the fallback rule

**Files:**
- Modify: `src/AI.Sentinel/SentinelAction.cs`
- Modify: `src/AI.Sentinel/Detection/DetectorConfiguration.cs`
- Modify: `src/AI.Sentinel/Detection/DetectionResult.cs`
- Modify: `src/AI.Sentinel/Detection/DetectionPipeline.cs`
- Modify: `src/AI.Sentinel/SentinelOptions.cs`
- Modify: `src/AI.Sentinel/ServiceCollectionExtensions.cs`, in `RegisterPipeline` and `BuildDetectionPipeline`
- Modify: `src/AI.Sentinel/Intervention/InterventionEngine.cs`
- Modify: `src/AI.Sentinel/Intervention/InterventionAppliedNotification.cs`
- Modify: `src/AI.Sentinel/SentinelPipeline.cs`, in `ScanAsync` and `AppendAuditAsync`
- Create: `src/AI.Sentinel/Detection/IRedactingDetector.cs`
- Create: `src/AI.Sentinel/Detection/RedactionSpan.cs`
- Create: `src/AI.Sentinel/SentinelActionRanking.cs`
- Test: `tests/AI.Sentinel.Tests/Intervention/EffectiveActionTests.cs`
- Test: `tests/AI.Sentinel.Tests/SentinelOptionsTests.cs`

**Interfaces:**
- Produces:
  - `SentinelAction.Redact`, appended last so existing numeric values don't change.
  - `DetectorConfiguration.Action`, type `SentinelAction?`.
  - `SentinelOptions.RedactByDefault` (bool, default true) and `SentinelOptions.RestoreRedactedValues` (bool, default true).
  - `public readonly record struct RedactionSpan(int Start, int Length, string EntityType)`.
  - `public interface IRedactingDetector : IDetector { IReadOnlyList<RedactionSpan> FindSpans(string text); }`.
  - `DetectionResult.ActionOverride`, type `SentinelAction?`, an `init` property rather than a positional parameter.
  - `SentinelOptions.EffectiveAction(DetectionResult d)`: returns `ActionFor(d.Severity)` when `ActionOverride` is null or Redact, otherwise the override.
  - `internal static class SentinelActionRanking { static SentinelAction MostRestrictive(IEnumerable<SentinelAction> actions); }`, in `src/AI.Sentinel/SentinelActionRanking.cs`, ranked `PassThrough < Log < Alert < Quarantine`. Redact never reaches it, because `EffectiveAction` has already resolved it.
  - `InterventionAppliedNotification` gains a last positional parameter, `IReadOnlyDictionary<string, int>? Redactions = null`.

- [ ] **Step 1: Write the failing tests:**
  - `Override_Quarantine_BeatsSeverityLog`: a Low detection with `ActionOverride = Quarantine` gets quarantined.
  - `Override_Log_LowersCritical`: a Critical detection with `ActionOverride = Log` gives no exception and publishes `Log`.
  - `MixedDetections_MostRestrictiveWins`: an Alert detection plus a Log detection publishes `Alert`.
  - `RedactOverride_InScan_FallsBackToSeverityAction`: a High detection with `ActionOverride = Redact` and `OnHigh = Alert` publishes `Alert`.
  - `RedactOverride_InScan_AuditSummaryEndsWithNotRedacted`, through `SentinelPipeline.ScanMessagesAsync`.
  - `RedactByDefault_SetsOverrideOnRedactingDetectorsOnly`: in `DetectionPipeline`, a fake `IRedactingDetector` gets `ActionOverride == Redact` and a plain `IDetector` gets null.
  - `RedactByDefaultFalse_LeavesOverrideNull`.
  - `ConfiguredAction_WinsOverRedactByDefault`.
  - `SeverityOption_SetToRedact_ThrowsOnAddAISentinel`: an `ArgumentException` that names `OnHigh`.
  - `RedactConfigured_OnNonRedactingDetector_ThrowsWhenPipelineBuilds`: an `InvalidOperationException` that names the detector type.
- [ ] **Step 2: Run them.** Expected: FAIL to compile or FAIL.
- [ ] **Step 3: Implement.**
  - `DetectionPipeline` takes a new constructor parameter `bool redactByDefault`. After severity clamping, it sets `ActionOverride = cfg?.Action ?? (detector is IRedactingDetector && redactByDefault ? Redact : null)` on non-clean results. It throws on `cfg.Action == Redact` for a detector that isn't an `IRedactingDetector`.
  - `InterventionEngine.Apply` and `SentinelPipeline.ScanAsync` use `MostRestrictive` over `EffectiveAction` instead of `ActionFor(MaxSeverity)`.
  - `AppendAuditAsync` appends `; not redacted` when `ActionOverride == Redact`.
- [ ] **Step 4: Run** `*EffectiveActionTests*`, `*SentinelOptionsTests*`, `*InterventionEngine*` and `*DetectionPipeline*`. Expected: PASS.
- [ ] **Step 5: Run the full suite.** Expect existing PII and credential tests to now see a fallback summary. Update their expected summaries. Their actions must stay as before.
- [ ] **Step 6: Commit** `feat(intervention): per-detector actions and a Redact action that falls back to the severity action`.

---

### Task 3: PiiLeakageDetector finds every span, including bare emails

**Files:**
- Modify: `src/AI.Sentinel/Detectors/Security/PiiLeakageDetector.cs`
- Test: `tests/AI.Sentinel.Tests/Detectors/Security/PiiLeakageDetectorSpanTests.cs`

**Interfaces:**
- Consumes: `IRedactingDetector` and `RedactionSpan` from Task 2.
- Produces: `PiiLeakageDetector : ILlmEscalatingDetector, IRedactingDetector`, with entity types `CREDIT_CARD`, `SSN`, `IBAN`, `BSN`, `NINO`, `PASSPORT`, `TAX_ID`, `EMAIL`, `PHONE`, `DATE_OF_BIRTH`.

- [ ] **Step 1: Write the failing tests.** Each asserts exact `(Start, Length, EntityType)` values:
  - `FindSpans_BareEmail_ReturnsEmailSpan`: `"mail jan@acme.nl now"` gives `(5, 11, "EMAIL")`.
  - `FindSpans_TwoIbansAndAPhone_ReturnsAllThree`.
  - `FindSpans_KeywordPrefixedTypes_SpanCoversValueOnly`: in `"BSN: 123456789"` the span covers `123456789`. The same rule applies to passport, tax ID and date of birth.
  - `FindSpans_CleanText_ReturnsEmpty`.
  - `AnalyzeAsync_BareEmail_IsMedium`: the reason is `Email address detected`.
- [ ] **Step 2: Run them.** Expected: FAIL.
- [ ] **Step 3: Implement.**
  - Add a `BareEmailPattern` and replace `EmailWithNamePattern` with it.
  - Give the keyword-prefixed patterns a named value group, so `FindSpans` can return just the value.
  - `FindSpans` runs every pattern with `Matches`.
  - `AnalyzeAsync` keeps its first-hit-by-severity order.
- [ ] **Step 4: Run** `*PiiLeakageDetector*`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(detectors): PII detector reports every match position and matches bare email addresses`.

---

### Task 4: CredentialExposureDetector spans and the reason leak

**Files:**
- Modify: `src/AI.Sentinel/Detectors/Security/CredentialExposureDetector.cs`
- Test: `tests/AI.Sentinel.Tests/Detectors/Security/CredentialExposureDetectorSpanTests.cs`

**Interfaces:**
- Produces: `CredentialExposureDetector : ILlmEscalatingDetector, IRedactingDetector`, with entity types `PASSWORD`, `API_KEY`, `SECRET_KEY`, `BEARER_TOKEN`, `AWS_SECRET`, `PRIVATE_KEY`, `GITHUB_TOKEN`.

- [ ] **Step 1: Write the failing tests:**
  - `FindSpans_ApiKeyAssignment_CoversValueOnly`: in `"api_key=abc123def"` the span covers `abc123def` with type `API_KEY`.
  - `FindSpans_BearerHeader_CoversToken`.
  - `FindSpans_PemBlock_CoversHeaderThroughEndMarker`.
  - `FindSpans_BarePrefixedTokens`: `ghp_…` gives `GITHUB_TOKEN` and `sk-…` gives `API_KEY`.
  - `AnalyzeAsync_Reason_ContainsNoPartOfTheSecret`: for each sample, assert the reason doesn't contain the value, nor any 4-character substring of it.
- [ ] **Step 2: Run them.** Expected: FAIL. The leak test fails on today's `match.Value[..20]`.
- [ ] **Step 3: Implement.**
  - Split the alternation into one pattern per type, each with a named value group.
  - The PEM pattern runs through `-----END … PRIVATE KEY-----`, or to the end of the text when there's no end marker.
  - The reason becomes `Credential exposure: <TYPE>`.
- [ ] **Step 4: Run** `*CredentialExposureDetector*`. Expected: PASS.
- [ ] **Step 5: Commit** `fix(detectors): credential detector no longer copies part of the secret into the audit summary`. Add `feat` wording for the spans in the body.

---

### Task 5: RedactionSession

**Files:**
- Create: `src/AI.Sentinel/Redaction/RedactionSession.cs`
- Test: `tests/AI.Sentinel.Tests/Redaction/RedactionSessionTests.cs`

**Interfaces:**
- Consumes: `IRedactingDetector` and `RedactionSpan`.
- Produces: `internal sealed class RedactionSession(IReadOnlyList<IRedactingDetector> redactors)` with these members:
  - `string Redact(string text)`.
  - `IReadOnlyList<ChatMessage> Redact(IReadOnlyList<ChatMessage> messages)`. It returns new `ChatMessage`s and new content objects, and never mutates its input. It covers `TextContent`, the string values in `FunctionCallContent.Arguments` (recursing into `JsonElement` objects and arrays), and `FunctionResultContent.Result` when that is a `string` or a `JsonElement`.
  - `object? RedactResult(object? result)`.
  - `string Restore(string text)`.
  - `IList<ChatMessage> Restore(IList<ChatMessage> messages)`. It covers `TextContent` and `FunctionCallContent.Arguments`.
  - `AIFunctionArguments Restore(AIFunctionArguments args)`.
  - `IReadOnlyDictionary<string, IReadOnlyDictionary<string, int>> CountsByDetector`, as detector id → type → count.
  - `bool HasRedactions`.

- [ ] **Step 1: Write the failing tests:**
  - `SameValueTwice_GetsSamePlaceholder`.
  - `TwoEmails_NumberedPerType`: the result is `[EMAIL_1]` and `[EMAIL_2]`, while an IBAN in the same text gets `[IBAN_1]`.
  - `ExistingPlaceholderInInput_NumberingSkipsPastIt_AndRestoreLeavesItLiteral`: the input `"[EMAIL_1] and jan@acme.nl"` redacts to `"[EMAIL_1] and [EMAIL_2]"`. Restoring that gives `"[EMAIL_1] and jan@acme.nl"`.
  - `OverlappingSpans_LongestWins` (Review Focus 2).
  - `MangledPlaceholder_NotRestored` (Review Focus 3).
  - `ValueSplitAcrossParts_EachPartHandledAlone_NoThrow` (Review Focus 1).
  - `FunctionCallArguments_NestedJsonStrings_Redacted`.
  - `FunctionResult_JsonElementString_Redacted`.
  - `Restore_FunctionCallArguments_RealValuesBack`.
  - `Redact_DoesNotMutateInput`.
  - `CountsByDetector_ReportsCountsOnly`: the counts contain no value.
- [ ] **Step 2: Run them.** Expected: FAIL.
- [ ] **Step 3: Implement.**
  - Scan the input for existing `\[([A-Z_]+)_(\d+)\]` tokens, and start each type's counter past the highest number found.
  - The restore map holds only the tokens this session created.
- [ ] **Step 4: Run** `*RedactionSessionTests*`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(redaction): per-call redaction session with numbered placeholders`.

---

### Task 6: Redact and restore in SentinelPipeline, non-streaming

**Files:**
- Modify: `src/AI.Sentinel/SentinelPipeline.cs`
- Modify: `src/AI.Sentinel/Detection/IDetectionPipeline.cs`
- Modify: `src/AI.Sentinel/Detection/DetectionPipeline.cs`
- Modify: `src/AI.Sentinel/Detection/DetectionPipelineInstrumented.cs`, which may be generated; adjust wherever it lives
- Create: `src/AI.Sentinel/Audit/AuditEntryRedactionExtensions.cs`
- Test: `tests/AI.Sentinel.Tests/Redaction/RedactionPipelineTests.cs`

**Interfaces:**
- Consumes:
  - `RedactionSession` from Task 5.
  - `ToolInvocationInterception.WrapTools` from Task 1.
  - `EffectiveAction` from Task 2.
- Produces:
  - `IReadOnlyList<IRedactingDetector> IDetectionPipeline.Redactors`: the enabled redacting detectors whose effective action is Redact.
  - `AuditEntryRedactionExtensions.Redaction(string detectorId, IReadOnlyDictionary<string, int> counts, string sessionId)`.
  - `const string RedactedPolicyCode = "REDACTED"`.

The flow in `GetResponseResultAsync`:
1. Create a `RedactionSession` from `pipeline.Redactors`, and redact `messageList`.
2. Scan the redacted list.
3. Wrap the tools. The interceptor restores the arguments, invokes the function, and returns `session.RedactResult(result)`.
4. Call the inner client with the hardened, redacted list.
5. Scan the response as it came back.
6. If `RestoreRedactedValues` is set, restore `response.Messages`.
7. When `session.HasRedactions`, append one redaction audit entry per detector and publish `InterventionAppliedNotification` with `Action = Redact` and `Redactions` set to the counts.

- [ ] **Step 1: Write the failing tests.** They use a fake inner model that records what it received, plus `UseFunctionInvocation` where noted:
  - `Prompt_WithEmail_ModelSeesPlaceholder_UserSeesRealValue`.
  - `Prompt_WithEmail_NoExceptionAndNoThreatDetectedNotification`.
  - `ToolCall_SentinelOutsideFunctionInvocation_ToolGetsRealValue_ModelNeverSeesIt`.
  - `ToolCall_SentinelInsideFunctionInvocation_ToolGetsRealValue_ModelNeverSeesIt`.
  - `ToolResult_ContainingIban_ReachesModelRedacted`, in both orders.
  - `History_AssistantTurnWithRealValue_RedactedOnNextCall`.
  - `RestoreDisabled_ReplyKeepsPlaceholders`.
  - `PromptInjectionPlusEmail_Quarantine_StillWins_NothingSent`.
  - `RedactByDefaultFalse_EmailBehavesAsBefore`.
  - `RedactionAuditEntry_IsSeverityNone_PolicyRedacted_CountsOnly`.
  - `NoOriginalValue_InAnyStoredAuditField`: search every string field of every stored entry.
  - `CallerChatOptions_NotMutated_AndNotDoubleWrapped` (Review Focus 4).
  - `ToolReturningPoco_PassesThroughUnchanged` (Review Focus 5).
- [ ] **Step 2: Run them.** Expected: FAIL.
- [ ] **Step 3: Implement** the flow above in `GetResponseResultAsync`.
- [ ] **Step 4: Run** `*RedactionPipelineTests*`, `*SentinelPipelineTests*` and `*SentinelChatClientTests*`. Expected: PASS.
- [ ] **Step 5: Run the full suite.**
- [ ] **Step 6: Commit** `feat!: redact PII and credentials before the prompt reaches the model`. The body says redaction is on by default for both detectors and closes #338. Add this footer:

```
BREAKING CHANGE: PiiLeakageDetector and CredentialExposureDetector now redact by default instead of
applying the severity action. A prompt with an email address or an API key reaches the model with a
placeholder and the call succeeds. Set opts.RedactByDefault = false to restore the previous behaviour.
```

---

### Task 7: Streaming restore

**Files:**
- Modify: `src/AI.Sentinel/SentinelPipeline.cs`, in `GetStreamingResultAsync`
- Test: `tests/AI.Sentinel.Tests/Redaction/RedactionStreamingTests.cs`

- [ ] **Step 1: Write the failing tests:**
  - `Streaming_PlaceholderSplitAcrossUpdates_Restored`: the updates are `"mail [EMA"`, `"IL_1] today"`, and the concatenated text the caller receives is `"mail jan@acme.nl today"`.
  - `Streaming_FunctionCallUpdate_ArgumentsRestored`.
  - `Streaming_UpdateCountAndNonTextContentPreserved`.
- [ ] **Step 2: Run them.** Expected: FAIL.
- [ ] **Step 3: Implement.** Apply the same pre-pass and tool wrapping as Task 6. After the response scan, restore the buffered updates:
  - Carry an unterminated `[`-prefix tail of one update's text into the next update.
  - Restore each update's `FunctionCallContent` arguments.
- [ ] **Step 4: Run** `*RedactionStreamingTests*` and `*SentinelChatClientStreamingTests*`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(redaction): restore placeholders in streamed replies`.

---

### Task 8: Redaction entries are informational everywhere

**Files:**
- Modify: `src/AI.Sentinel.AspNetCore/DashboardHandlers.cs`, around lines 38-50, 98-120, 210-222 and 369-380
- Modify: `src/AI.Sentinel.AspNetCore/wwwroot/sentinel.css`
- Modify: `src/AI.Sentinel.OpenTelemetry/OpenTelemetryAuditForwarder.cs:60-67`
- Test: `tests/AI.Sentinel.Tests/AspNetCore/RedactionDashboardTests.cs`
- Test: `tests/AI.Sentinel.OpenTelemetry.Tests/` (one new test)

- [ ] **Step 1: Write the failing tests:**
  - `RedactionEntry_NotCountedInSeverityTiles`.
  - `RedactionEntry_NotCountedInTrendBuckets`: today, `count++` runs for every entry.
  - `RedactionEntry_RiskScoreUnchanged`.
  - `RedactionEntry_FeedRow_HasRedactedBadge`.
  - `OpenTelemetry_RedactionEntry_LogsAtInformation`: today `None` maps to Debug, which default log filters drop, so the compliance evidence would be lost.
- [ ] **Step 2: Run them.** Expected: FAIL.
- [ ] **Step 3: Implement.**
  - Skip `PolicyCode == "REDACTED"` in the tiles and the trend.
  - Render a `redacted` badge in the feed row, and add a feed filter chip if the existing chip mechanism makes it cheap.
  - In OpenTelemetry, map `Severity.None` with `PolicyCode == "REDACTED"` to `LogLevel.Information`.
  - Check the Azure Sentinel forwarder, and confirm that `SentinelMetrics.Threats` and the alert sink only see detections. Redaction entries never come from `PipelineResult`, so expect nothing to change there. Add an assertion to `RedactionPipelineTests` that `Threats` doesn't move for a pure redaction.
- [ ] **Step 4: Run** the new tests plus `*Dashboard*`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(dashboard): show redactions as informational, outside the threat counts`.

---

### Task 9: Documentation

**Files:**
- Modify: `README.md`. Change the actions table near line 464, the EU AI Act Art. 10 row at line 285, and the per-detector configuration section. Add a GDPR line under the EU AI Act table.
- Create: `website/docs/redaction.md`. Place it in the sidebar next to the existing actions and detectors pages.
- Modify: `website/docs/approvals/` and the hook/MCP docs. Add one line each saying Redact falls back in 3.0.

- [ ] **Step 1: Write the content.** Use the spec's framing: "allow, minus the sensitive parts". Cover placeholders, restoring, the opt-out, fallback, what is audited, that the mapping is never stored, `RedactByDefault = false`, and the builder-order independence.
- [ ] **Step 2: Run** `dotnet test --filter-class "*DetectorDocumentationTests*"`, which checks the detector docs, and build the website if the repo has a docs build script. Expected: PASS.
- [ ] **Step 3: Commit** `docs: document redaction and the 3.0 default`.
- [ ] **Step 4: Run the full suite, push, and open the PR closing #338.** After merging, confirm the `feat!` entry and the breaking-change note appear in release PR #346.
