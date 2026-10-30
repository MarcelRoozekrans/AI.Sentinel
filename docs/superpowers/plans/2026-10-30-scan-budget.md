# Scan Budget Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** In-process and MCP scans judge only new content, bound it with `SentinelOptions.MaxScanBytes`, and fail closed on regex timeouts and oversize content (#439).

**Architecture:** `SentinelContext` gains a budget-cut view of the new messages. `DetectionPipeline` turns a `RegexMatchTimeoutException` into a Critical finding of the detector that threw, and adds one Critical `SEC-00` finding when the new content exceeded the budget. Content detectors switch to the new view. The MCP proxy stops pre-truncating and lets the pipeline cut.

**Tech Stack:** .NET 10, C#, Microsoft.Extensions.AI, xUnit v3, ZeroAlloc.Validation.

**Spec:** `docs/superpowers/specs/2026-10-30-scan-budget-design.md`

## Global Constraints

- Default `MaxScanBytes` = `262144`, the same as `SENTINEL_MCP_MAX_SCAN_BYTES`.
- Oversize and timeout findings are `Severity.Critical`.
- Oversize detector id: `SEC-00`. It belongs to no `IDetector`.
- `SentinelContext.TextContent` keeps its meaning: the whole conversation.
- Commits: one per task, conventional type `feat` or `fix` without `!`; the PR squashes to `feat:` → 4.2.0. No Co-Authored-By trailer, no "Generated with" line, no session links, no nested parentheses in commit bodies.
- Budget counts UTF-8 bytes of message detection text; the single-space separators between messages are not counted. A cut never splits a surrogate pair.
- "Fits" is `<=`: content exactly at the budget is not oversize.
- Run tests with `dotnet test tests/AI.Sentinel.Tests -- --filter-class "*<Class>"` (xUnit v3 MTP); full run per the AOT note: build, then run the test DLL with `-noclass "*DetectorRegistrationTrimTests"`.

## Review Focus

1. Multi-byte text at the cut, such as emoji or CJK right at the budget edge: the cut stays valid UTF-16 and the byte count is exact. Test in Task 1.
2. A streamed response over the budget: the streaming leg must block it just like the non-streaming leg. Test in Task 2.
3. A named pipeline: it inherits `MaxScanBytes` from the default unless it sets its own. Test in Task 2.
4. A host with `OnCritical = Log`: `SEC-00` and the timeout findings go through the normal action mapping, so they are logged, not force-blocked. Test in Task 2.
5. A Claude Code hook given a huge tool result: it reports `SEC-00` and blocks, rather than failing as an internal error. Test in Task 2.

---

### Task 1: Budget-cut new-message view on `SentinelContext`

**Files:**
- Modify: `src/AI.Sentinel/Detection/SentinelContext.cs`
- Create: `src/AI.Sentinel/Detection/Utf8Text.cs`
- Modify: `src/AI.Sentinel.Detectors.Sdk/SentinelContextBuilder.cs`
- Test: `tests/AI.Sentinel.Tests/Detection/SentinelContextScanBudgetTests.cs`, `tests/AI.Sentinel.Detectors.Sdk.Tests/` (builder test, next to the existing `WithNewMessagesFrom` test)

**Interfaces:**
- Produces:
  - `public int? MaxScanBytes { get; init; }` on `SentinelContext`. `null` means unlimited, and is the default. A value `<= 0` throws `ArgumentOutOfRangeException` in the init.
  - `public IReadOnlyList<string> NewMessageTexts { get; }`, cached. It has one entry per message from `NewMessagesFrom` on, each `MessageText(message)`, cut in order so the sum of UTF-8 bytes is at most `MaxScanBytes`. A message past the budget yields `""`.
  - `public string NewTextContent { get; }`, cached: `string.Join(" ", NewMessageTexts)`.
  - `internal string NewProseContent { get; }`, cached: the `Text ?? ""` of the new messages, cut by the same rule independently, joined by `" "`.
  - `public long NewContentBytes { get; }`: the UTF-8 byte total of the uncut new detection texts.
  - `public bool ExceedsScanBudget { get; }`: `MaxScanBytes is { } max && NewContentBytes > max`.
  - `internal static class Utf8Text { static string Truncate(string text, int maxBytes); }`: the longest prefix within `maxBytes` that doesn't end in a lone high surrogate. It returns the same instance when the text fits.
  - `SentinelContextBuilder.WithMaxScanBytes(int? maxBytes)`.

- [ ] **Step 1: Write the failing tests** in `SentinelContextScanBudgetTests`:
  - `NewMessageTexts_HoldsOnlyMessagesFromNewMessagesFrom`: 3 messages, `NewMessagesFrom = 2`, so a count of 1 that equals the third message's text.
  - `NoBudget_NothingIsCut`: `MaxScanBytes = null`, a 1 MB message, so `ExceedsScanBudget` is false and the text is unchanged.
  - `ExactlyAtBudget_IsNotOversize`: new texts of 6 and 4 bytes with `MaxScanBytes = 10`, so `ExceedsScanBudget` is false and both texts are whole.
  - `OverBudget_CutsInMessageOrder`: texts `"aaaaaa"` and `"bbbbbb"` with `MaxScanBytes = 8`, so the texts are `["aaaaaa", "bb"]`, `NewContentBytes == 12` and `ExceedsScanBudget` is true.
  - `PastBudget_LaterMessagesAreEmpty`: 3 texts of 5 bytes with a budget of 5, giving `["xxxxx", "", ""]`.
  - `Cut_NeverSplitsSurrogatePair`: `"ab😀"` (2 + 4 bytes) with a budget of 4 yields `"ab"`. `"ab😀"` with a budget of 6 is whole.
  - `Cut_MultiByteCjk`: `"日本語"` (9 bytes) with a budget of 7 yields `"日本"`.
  - `ToolResultCountsTowardBudget`: a tool message holding a 100-byte `FunctionResultContent` with a budget of 50, so `ExceedsScanBudget` is true.
  - `NewProseContent_ExcludesToolTraffic`.
  - `ZeroOrNegativeBudget_Throws`.
  - Builder test: `WithMaxScanBytes(10)` flows into `ctx.MaxScanBytes`.
- [ ] **Step 2: Run them.** `dotnet test tests/AI.Sentinel.Tests -- --filter-class "*SentinelContextScanBudgetTests"` should fail to compile, because the members don't exist yet.
- [ ] **Step 3: Implement the members.** Compute `NewMessageTexts` and `NewContentBytes` together in one lazy pass, with `Encoding.UTF8.GetByteCount` per text and a running remainder. `Utf8Text.Truncate` walks back from `Encoding.UTF8.GetMaxCharCount` bounds, or uses the encoder, to the char boundary.
- [ ] **Step 4: Run the tests again.** Expect PASS. Also run `--filter-class "*SentinelContextNewMessagesTests"` and expect PASS.
- [ ] **Step 5: Commit** with `feat(detection): budget-cut view of the new messages on SentinelContext (#439)`.

### Task 2: `MaxScanBytes` option and the Critical `SEC-00` finding

**Files:**
- Modify: `src/AI.Sentinel/SentinelOptions.cs`. Add the option near `SessionIdleTimeout`, with `[GreaterThan(0, ErrorCode = "GreaterThan")]`.
- Modify: `src/AI.Sentinel/SentinelPipeline.cs`. In `BuildContext`, set `MaxScanBytes = options.MaxScanBytes` in both branches.
- Modify: `src/AI.Sentinel/Detection/DetectionPipeline.cs`.
- Modify docs:
  - The options reference under `website/docs/configuration/`; grep for `SessionIdleTimeout` to find it.
  - `website/docs/detectors/security.md` and `overview.md`: add a `SEC-00` row "Scan limit", labelled as a pipeline finding.
  - `README.md`: the detector table, if it lists ids.
  - The OWASP mapping tables: `SEC-00` maps to LLM10 Unbounded Consumption. Grep for `LLM10`.
- Modify: `tests/AI.Sentinel.Tests/DetectorDocumentationTests.cs`, and any registration or preset test that enumerates ids, so that `SEC-00` is accepted as a documented pipeline id with no `IDetector`.
- Test: `tests/AI.Sentinel.Tests/Detection/ScanBudgetPipelineTests.cs`, plus a hook test in `tests/AI.Sentinel.Tests/ClaudeCode/`.

**Interfaces:**
- Consumes: from Task 1, `SentinelContext.MaxScanBytes`, `ExceedsScanBudget` and `NewContentBytes`.
- Produces:
  - `public int MaxScanBytes { get; set; } = 262144;` on `SentinelOptions`. The named-pipeline copy carries it, because the options object is copied with `MemberwiseClone`.
  - `internal static readonly DetectorId ScanLimitId = new("SEC-00");` on `DetectionPipeline`.
  - The finding's reason is `$"New content is {total} bytes; only the first {max} were scanned. Raise SentinelOptions.MaxScanBytes to scan more."`

- [ ] **Step 1: Write the failing tests** in `ScanBudgetPipelineTests`, using the pipeline the way `SentinelPipelineNewMessagesTests` does:
  - `Oversize_AddsCriticalSec00`: `MaxScanBytes = 100` and a 200-byte user message give a detection with id `SEC-00` and `Severity.Critical`, and the result is `ThreatDetected` with Quarantine.
  - `AtBudget_NoSec00`: exactly 100 bytes, so the scan is clean.
  - `Oversize_HeadStillScanned`: a credential in the first 100 bytes of a 200-byte message reports both `SEC-02`, or whatever `CredentialExposureDetector`'s id is, and `SEC-00`.
  - `Oversize_NotAffectedByActionOverridesOrCap`: setting `SeverityCap = Low` on every detector leaves `SEC-00` Critical.
  - `OnCriticalLog_Sec00IsLoggedNotBlocked`: `OnCritical = Log` lets the call through, and the audit has `SEC-00`. (Review Focus 4)
  - `Streaming_OversizeResponse_Blocked`: the inner client streams a 200-byte response with `MaxScanBytes = 100`, and the streaming result is `ThreatDetected` with `SEC-00`. (Review Focus 2)
  - `NamedPipeline_InheritsMaxScanBytes` and `NamedPipeline_OwnMaxScanBytesWins`. (Review Focus 3)
  - `NoDetectors_OversizeStillReported`.
  - `MaxScanBytes_Zero_FailsValidation`, in `SentinelOptionsTests`.
  - Hook test: a PostToolUse with a tool result of `MaxScanBytes + 1` bytes decides block, with `SEC-00` in the output, and is not an internal error. (Review Focus 5)
- [ ] **Step 2: Run them.** `--filter-class "*ScanBudgetPipelineTests"` should FAIL, because the option doesn't exist yet.
- [ ] **Step 3: Implement.**
  - Add the option and wire `BuildContext`.
  - In `DetectionPipeline.RunAsync`, after `ApplyActionOverrides`, append `DetectionResult.WithSeverity(ScanLimitId, Severity.Critical, reason)` when `ctx.ExceedsScanBudget`, before `BuildResult`. Apply the same on the zero-detector early return.
  - Update the docs and the doc tests.
- [ ] **Step 4: Run the tests again.** `ScanBudgetPipelineTests`, `SentinelOptionsTests`, `DetectorDocumentationTests`, `NamedPipelineTests` and the hook tests should all PASS.
- [ ] **Step 5: Commit** with `feat(pipeline): SentinelOptions.MaxScanBytes, oversize new content is a Critical SEC-00 finding (#439)`.

### Task 3: A regex timeout fails closed

**Files:**
- Modify: `src/AI.Sentinel/Detection/DetectionPipeline.cs`, in `SafeAnalyzeAsync`, and update its remarks.
- Test: `tests/AI.Sentinel.Tests/Detection/DetectorFailureIsolationTests.cs`

**Interfaces:**
- Produces:
  - A `catch (RegexMatchTimeoutException ex)` placed before the generic catch. It returns `DetectionResult.WithSeverity(detector.Id, Severity.Critical, $"Regex timed out after {ex.MatchTimeout.TotalMilliseconds:0} ms; content could not be judged.")`.
  - It logs a warning and invokes `_onDetectorFailure` with `$"AI.Sentinel: detector {id} timed out and was flagged Critical for this scan."`
  - `outcomes[index]` stays null, so the semantic cap and review do not touch the result.

- [ ] **Step 1: Write the failing tests:**
  - `RegexTimeout_IsCriticalNotClean`: a test detector throws `new RegexMatchTimeoutException("x", "p", TimeSpan.FromSeconds(1))`, so the result is Critical with that detector's id.
  - `RegexTimeout_SeverityCapApplies`: `SeverityCap = Medium` makes it Medium.
  - `RegexTimeout_InSemanticRuleLayer_NotSemanticCapped`: a `SemanticDetectorBase` test subclass whose rule layer throws the timeout stays Critical with the default semantic cap.
  - `RegexTimeout_ReportsTimedOutWording`: the failure sink gets the new message.
  - `OtherException_StillClean`: the existing behaviour, kept.
  - `RealCatastrophicRegex_FailsClosed`: a detector using `new Regex("(a+)+$", RegexOptions.None, TimeSpan.FromMilliseconds(10))` on `new string('a', 5000) + "!"` gives Critical.
- [ ] **Step 2: Run them.** `--filter-class "*DetectorFailureIsolationTests"` should FAIL on the new tests.
- [ ] **Step 3: Implement the catch** as described in Interfaces.
- [ ] **Step 4: Run the tests again.** Expect PASS.
- [ ] **Step 5: Commit** with `fix(detection): a regex timeout is a Critical finding, not Clean (#439)`.

### Task 4: Content rule detectors judge only new messages

**Files:**
- Modify (switch to the Task 1 view):
  - `Detectors/Security/CredentialExposureDetector.cs` and `PiiLeakageDetector.cs`: `ctx.TextContent` becomes `ctx.NewTextContent`.
  - `Detectors/Operational/PlaceholderTextDetector.cs` and `RepetitionLoopDetector.cs`: `ctx.ProseContent` becomes `ctx.NewProseContent`.
  - `Detectors/Security/AdversarialUnicodeDetector.cs`, `Detectors/Operational/WrongLanguageDetector.cs` and `Detectors/Security/EntropyCovertChannelDetector.cs`: iterate `ctx.NewMessageTexts`, or the new messages' text where the detector reads `Text` only, instead of every message.
  - `Detectors/Operational/IncompleteCodeBlockDetector.cs` and `TruncatedOutputDetector.cs`: join only the new messages' `Text`, cut. Use a prose-cut list; if per-message prose is needed, expose `internal IReadOnlyList<string> NewMessageProse` in `SentinelContext` alongside `NewProseContent`.
  - Leave unchanged: `ToolCallFrequencyDetector`, `UnboundedConsumptionDetector`, `SystemPromptEchoDetector`, `OutputSchemaDetector` and `BlankResponseDetector`. Before switching each detector, confirm it against the spec's rule: judges content means move, a whole-conversation property means keep. Record any deviation in the commit body.
- Modify: if `ProseContent` has no users left, delete it.
- Test: each detector's existing test file under `tests/AI.Sentinel.Tests/Detectors/`, plus `tests/AI.Sentinel.Tests/SentinelPipelineNewMessagesTests.cs`.

**Interfaces:**
- Consumes: from Task 1, `NewTextContent`, `NewProseContent` and `NewMessageTexts`.

- [ ] **Step 1: Write the failing tests:**
  - Per moved detector, `<Detector>_IgnoresHistory`: the triggering text sits in a message before `NewMessagesFrom`, so the result is Clean. Also `<Detector>_FlagsNewMessage`, the same text after it, so the detector fires.
  - Pipeline: `ToolLoop_SecretInRound1Result_FlaggedOnceNotInRound2`. Two `GetResponseAsync` round trips through `UseAISentinel()`, where round 1's tool result carries an AWS key. Round 1 reports the credential finding. Round 2 has history `[user, assistant(call), tool(result-with-key), assistant(call2), tool(clean)]` and reports no credential finding.
  - `Oversize_CredentialPastCap_NotReportedButScanCritical`: a credential past `MaxScanBytes` gives no credential finding, but `SEC-00` makes the scan Critical.
- [ ] **Step 2: Run them.** `--filter-class "*Detector*Tests"` and `--filter-class "*SentinelPipelineNewMessagesTests"` should FAIL on the history tests.
- [ ] **Step 3: Switch each detector** as listed in Files.
- [ ] **Step 4: Run the tests again.** Expect PASS. Then run the full `AI.Sentinel.Tests` suite to catch tests that relied on history scanning, and update those whose premise was history.
- [ ] **Step 5: Commit** with `feat(detectors): content rule detectors judge only the new messages (#439)`.

### Task 5: Semantic detectors score the budget-cut texts

**Files:**
- Modify: `src/AI.Sentinel/Detection/SemanticDetectorBase.cs`. In `NewMessageTexts`, `RoleOf` and `TextsToEmbed`, under `_tracksRoles`, read `ctx.NewMessageTexts[i - ctx.NewMessagesFrom]` instead of `SentinelContext.MessageText(ctx.Messages[i])`. Update the doc comment on `GetTextsToScore`. Leave the legacy `GetText` override path and a `GetTextsToScore` override untouched.
- Test: `tests/AI.Sentinel.Tests/Detection/SemanticDetectorBaseTests.cs`

**Interfaces:**
- Consumes: from Task 1, `NewMessageTexts`.

- [ ] **Step 1: Write the failing tests:**
  - `DefaultTexts_AreBudgetCut`: a recording fake generator, `MaxScanBytes = 10`, and two new messages of 8 bytes each, so the embedded texts are `["<8 bytes>", "<2 bytes>"]`.
  - `PastBudgetMessage_NotEmbedded`: its `""` is dropped as blank.
  - `RoleOf_MatchesCutText`: a candidate from the cut message still carries its role.
  - `GetTextsToScoreOverride_NotCut`: it keeps what the override returns.
- [ ] **Step 2: Run them.** `--filter-class "*SemanticDetectorBaseTests"` should FAIL.
- [ ] **Step 3: Implement** as described in Files.
- [ ] **Step 4: Run the tests again.** `SemanticDetectorBaseTests`, `EmbedOncePerScanTests` and `RuleFastPathTests` should PASS. ComplianceEval scores must not change: run the eval test project or the tool the repo uses (grep `ComplianceEval`) and compare against main.
- [ ] **Step 5: Commit** with `feat(detection): semantic detectors score the budget-cut new messages (#439)`.

### Task 6: The MCP proxy cuts in the pipeline and blocks oversize content

**Files:**
- Modify: `src/AI.Sentinel.Mcp/McpPipelineFactory.cs`. Take `int maxScanBytes` and set `MaxScanBytes = maxScanBytes` on the options. Thread it from `ProxyCommand`/`McpProxy`, where `maxScanBytes` is already passed.
- Modify: `src/AI.Sentinel.Mcp/MessageBuilder.cs`. `BuildToolCallRequest`, `BuildToolCallResponse` and `BuildPromptGetResponse` no longer call `TruncateIfNeeded`. `CollectRedactable` and `RedactableCollector` no longer split items into `Oversize`: every allowlisted text item is redactable content. Remove the `Oversize` tuple member and its callers in `ToolCallInterceptor` and `PromptGetInterceptor`. Delete `TruncateIfNeeded` if unused. Drop the `maxScanBytes` parameters that become unused.
- Modify: `src/AI.Sentinel.Mcp/ResourceReadInterceptor.cs`. An item over the budget is no longer skipped. It is scanned, or redacted then scanned, so the pipeline reports `SEC-00` and the read is blocked. Remove `LogOversize`, or keep it as a log line before the scan; the builder chooses. Update the class remarks.
- Modify: `website/docs/integrations/mcp-proxy.md` and `website/docs/redaction.md`. `SENTINEL_MCP_MAX_SCAN_BYTES` content over the budget is now blocked as `SEC-00`, not skipped or truncated.
- Test: `tests/AI.Sentinel.Tests/Mcp/MessageBuilderTests.cs`, `ResourceReadInterceptorTests.cs`, `McpRedactionProxyTests.cs` and `McpPipelineFactoryTests.cs`.

**Interfaces:**
- Consumes: Task 2's `SentinelOptions.MaxScanBytes` and `SEC-00`.

- [ ] **Step 1: Write the failing tests:**
  - `ToolResultOverBudget_BlockedWithSec00`, in both the non-redacting and redacting proxies: the agent gets the `McpProtocolException`, and the audit has `SEC-00`.
  - `ToolResultInjectionPastCap_Blocked`: a prompt-injection string placed after `maxScanBytes` bytes of filler is blocked. This is the original bypass.
  - `ResourceReadOverBudget_Blocked`: it was skipped before.
  - `PromptGetOverBudget_Blocked`.
  - `FactorySetsMaxScanBytes`.
  - Update the `MessageBuilderTests` that asserted truncation, so they assert the text is whole.
- [ ] **Step 2: Run them.** `--filter-class "*Mcp*"` should FAIL on the new tests.
- [ ] **Step 3: Implement** as described in Files.
- [ ] **Step 4: Run the tests again.** `--filter-class "*Mcp*"` should PASS.
- [ ] **Step 5: Commit** with `fix(mcp): content over SENTINEL_MCP_MAX_SCAN_BYTES is blocked as SEC-00, not forwarded unscanned (#439)`.

### Task 7: Full verification

- [ ] **Step 1:** `dotnet build AI.Sentinel.slnx -c Release` with 0 warnings. The repo treats warnings as errors.
- [ ] **Step 2:** Run the full test suite, with the test DLL run with `-noclass "*DetectorRegistrationTrimTests"`, and expect all to pass. Run the AOT trim test separately if the environment allows.
- [ ] **Step 3:** Check the public API baseline. If the repo has `PublicAPI.Shipped/Unshipped.txt` or an API approval test, add the new public members: `SentinelContext.MaxScanBytes`, `NewMessageTexts`, `NewTextContent`, `NewContentBytes` and `ExceedsScanBudget`; `SentinelOptions.MaxScanBytes`; and `SentinelContextBuilder.WithMaxScanBytes`. This is folded into the task that adds them if a test fails there.
