# Second-Stage Review (#511, PR 1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make embedding hits triage-only, capped at Medium, and route every second-stage check through a pluggable `IDetectionReviewer`. The reviewer is reachable from `SentinelOptions` and from the CLI hosts' environment, and is measured by ComplianceEval on a fit/held-out split.

**Architecture:**
- `SemanticDetectorBase`'s internal scoring path returns its result plus a review candidate: the text, its score and its role.
- `DetectionPipeline` applies the configured Floor/Cap and then the semantic cap, and picks review candidates. It reviews the top `MaxReviewsPerScan` candidates concurrently under `ReviewTimeout`, then re-applies Floor/Cap.
- The old `EscalateAllAsync`/`EscalateAsync` code becomes `LlmJudgeReviewer`, one `IDetectionReviewer` among future others (#304).

**Tech Stack:** .NET 10 (SDK 10.0.403 pinned in `global.json`), Microsoft.Extensions.AI, xUnit v3, System.Text.Json source generation (AOT), System.Diagnostics.Metrics.

**Spec:** `docs/superpowers/specs/2026-10-30-second-stage-review-design.md`. Read it first. D1–D7 are Marcel's decisions, and C0–C7 are rules this plan implements literally.

## Global Constraints

- Branch `feat/511-second-stage-review`, already created from a fresh `origin/main` with the spec committed.
- One commit per task. Commit messages follow conventional commits.
  - **No `Co-Authored-By` trailer, no "Generated with Claude Code" line, no session links.**
  - **No nested parentheses in commit bodies**: write `typeof IDetector`, not `typeof(IDetector)` inside a parenthesised phrase.
- Tasks 3 and 4 are `feat!` commits with a `BREAKING CHANGE:` footer, which yields 4.0.0.
- Defaults:
  - `MaxReviewsPerScan = 4`; 0 disables review; negative is rejected.
  - `ReviewTimeout = 5 s`, and 3 s in the hook CLIs.
  - Semantic cap = `Severity.Medium`.
  - `ReviewThreshold` defaults to `LowThreshold`.
- Truncation to the last 64 KiB (`MaximumEscalationCharacters`) and #515's prompt hardening are kept unchanged in `LlmJudgeReviewer`. The hardening consists of the per-call random boundary, the treat-as-data instruction, the JSON-only answer and `TryParseVerdict`.
- Metric `sentinel.reviews`, tags:
  - `outcome` ∈ `confirmed|raised|lowered|cleared|no_verdict|failed|timed_out|over_budget`;
  - `detector` = detector ID.
- The public `SemanticDetectorBase.AnalyzeAsync(ctx, ct)` stays uncapped, with unchanged results.
- Fast-path regex matches are never capped and never reviewed.
- Environment variables, exact names: `SENTINEL_REVIEW_ENDPOINT`, `SENTINEL_REVIEW_MODEL`, `SENTINEL_REVIEW_API_KEY`, `SENTINEL_REVIEW_MAX_PER_SCAN`, `SENTINEL_REVIEW_TIMEOUT_MS`.
- Test command, excluding the AOT publish test: `dotnet test tests/AI.Sentinel.Tests --filter-not-class "*DetectorRegistrationTrimTests"`. The SDK tests use `dotnet test tests/AI.Sentinel.Detectors.Sdk.Tests`.
- Warnings are errors in this repo (analyzers on). A build with new warnings is a failed step.

## Review Focus

1. **A reviewer that ignores its cancellation token and never returns.** The timeout must still end the review: wait with `WaitAsync(timeout, ct)`, don't just rely on the token. The result is the capped one with outcome `timed_out`. → Task 5, `Review_ReviewerIgnoresToken_TimesOutAndKeepsCappedResult`.
2. **The caller cancels during review.** `OperationCanceledException` propagates, the review is not counted as `failed` or `timed_out`, and no warning is logged. → Task 5, `Review_CallerCancels_Propagates`.
3. **A reviewer that throws synchronously**, before returning a `ValueTask`. It is treated like a faulted task: outcome `failed`, capped result. → Task 5, `Review_ReviewerThrowsSynchronously_KeepsCappedResult`.
4. **A reviewer reason with newlines, control characters or 10 KB of text.** The result reason is sanitised to one line and at most 200 characters, like rule-match reasons, so it can't forge audit lines. → Task 5, `Review_ReasonIsSanitisedAndTruncated`.
5. **A conversation of more than 16 new messages** where the flagged text is in the folded first input. The candidate role is the newest contributor's role, not null, and not an exception. → Task 2, `Candidate_FoldedText_UsesNewestContributorRole`.

---

### Task 1: Public review API and `LlmJudgeReviewer`

**Files:**
- Create: `src/AI.Sentinel/Detection/IDetectionReviewer.cs`, which holds the interface plus `ReviewRequest` and `ReviewVerdict`.
- Create: `src/AI.Sentinel/Detection/LlmJudgeReviewer.cs`.
- Modify: `src/AI.Sentinel/Detection/DetectionPipeline.cs`. Move `TryParseVerdict`, `LastPart` and `MaximumEscalationCharacters` into `LlmJudgeReviewer`. Leave `EscalateAsync` calling the moved helpers for now; Task 5 deletes it.
- Test: `tests/AI.Sentinel.Tests/Detection/LlmJudgeReviewerTests.cs`.

**Interfaces:**
- Produces, exactly as in spec D3:
  ```csharp
  public interface IDetectionReviewer { ValueTask<ReviewVerdict> ReviewAsync(ReviewRequest request, CancellationToken cancellationToken); }
  public sealed record ReviewRequest(DetectorId DetectorId, string Criterion, string Text, ChatRole? Role, float? Score, Severity ProposedSeverity, Severity MaximumSeverity);
  public sealed record ReviewVerdict(Severity? Severity, string Reason) { public static ReviewVerdict None { get; } = new(null, string.Empty); }
  public sealed class LlmJudgeReviewer(IChatClient client) : IDetectionReviewer
  ```
  `Role` is `ChatRole?`, per spec C0d.
- `internal static bool LlmJudgeReviewer.TryParseVerdict(string? text, out Severity severity)` is moved unchanged. Its existing tests in `DetectionPipelineTests` move to the new test file.

- [ ] **Step 1: Write the failing tests** in `LlmJudgeReviewerTests`, using the existing `CapturingChatClient` pattern from `DetectionPipelineTests`. Move that helper to `tests/AI.Sentinel.Tests/Helpers/CapturingChatClient.cs`.
  - `ReviewAsync_SendsCriterionProposedSeverityAndFencedText`: the system message contains `request.Criterion` and `"Medium"`. The user message is `<flagged_content_{32 hex}>\n{text}\n</flagged_content_…>`, and both tags carry the same boundary.
  - `ReviewAsync_ParsesSeverityAndReason`: the reply `{"severity":"High","reason":"clear override"}` gives `ReviewVerdict(Severity.High, "clear override")`.
  - `ReviewAsync_UnparseableReply_ReturnsNone`: the reply `"I think it is bad"` gives `ReviewVerdict.None`.
  - `ReviewAsync_TextOver64KiB_SendsLast64KiB`: the same assertion as today's `EscalateAsync_LargeMessage_ClassifierSeesItsLast64KiB`.
  - `ReviewAsync_ClientThrows_Propagates`: the reviewer does **not** swallow the exception, because the pipeline classifies failures in Task 5.
  - Move the existing `TryParseVerdict` cases, such as "Critical in reason is not a verdict", unchanged.
- [ ] **Step 2: Run them.** `dotnet test tests/AI.Sentinel.Tests --filter-class "*LlmJudgeReviewerTests"`. Expected: compile failure, because `LlmJudgeReviewer` does not exist.
- [ ] **Step 3: Implement.**
  - The prompt keeps today's hardening sentences verbatim. Replace "A rule-based detector (rule ID: X) flagged incoming content at severity S. Your task: assess whether the content justifies S severity or should be lower." with three parts:
    1. "Detector {id} looks for: {criterion}";
    2. "It proposed severity {proposed}; the highest severity you may give is {maximum}.";
    3. "Decide whether the content matches what the detector looks for, and at which severity. Answer None if it does not."
  - Read `reason` from the JSON with the same tolerant extraction as `severity`, and default it to empty.
- [ ] **Step 4: Run them.** The same command passes. Then run the full test command: the existing `DetectionPipelineTests` still pass.
- [ ] **Step 5: Commit.** `feat(detection): IDetectionReviewer and the LLM judge as its first implementation`

---

### Task 2: Review candidates from semantic scoring

**Files:**
- Create: `src/AI.Sentinel/Detection/SemanticOutcome.cs`, internal.
- Modify: `src/AI.Sentinel/Detection/SemanticDetectorBase.cs`, covering both internal `AnalyzeAsync` overloads, `Score`, `Classify` and `SelectTextsToScore`.
- Modify: `src/AI.Sentinel/Detection/DetectorConfiguration.cs`, adding `ReviewThreshold`.
- Modify: `src/AI.Sentinel/ServiceCollectionExtensions.cs`, in the threshold validation near line 225: `ReviewThreshold` is in (0, 1], is not above a set `MediumThreshold`, and is rejected on non-semantic detectors with the same message pattern as High/Medium.
- Modify: `src/AI.Sentinel/Detection/DetectionPipeline.cs`, in `SafeAnalyzeAsync`. It now gets a `SemanticOutcome` from the semantic paths and stores the candidate per index, in an array local to `RunAsync`. No behaviour change yet.
- Test: `tests/AI.Sentinel.Tests/Detection/ReviewCandidateTests.cs`, and `DetectorOptInAndThresholdTests.cs` for validation.

**Interfaces:**
- Produces:
  ```csharp
  internal readonly record struct ReviewCandidate(string Text, float Score, ChatRole? Role);
  internal readonly record struct SemanticOutcome(DetectionResult Result, ReviewCandidate? Candidate, bool FromFastPath);
  // SemanticDetectorBase
  protected virtual float ReviewThreshold => LowThreshold;
  internal float EffectiveReviewThreshold(DetectorConfiguration? configuration);   // configuration?.ReviewThreshold ?? ReviewThreshold
  internal Severity MaximumBucketSeverity { get; }                                 // max of High/Medium/LowSeverity
  internal ValueTask<SemanticOutcome> AnalyzeAsync(SentinelContext ctx, DetectorConfiguration? configuration, CancellationToken ct);
  internal ValueTask<SemanticOutcome> AnalyzeAsync(SentinelContext ctx, DetectorConfiguration? configuration, EmbeddingScope scope, ScanEmbeddings scan, IReadOnlyList<string> texts, CancellationToken ct);
  internal float EvaluationReviewThreshold => ReviewThreshold;   // for ComplianceEval
  // DetectorConfiguration
  public float? ReviewThreshold { get; set; }
  ```
  The public `AnalyzeAsync(ctx, ct)` returns `.Result` of the first overload.
- **Candidate rule, from spec C0c:**
  - If any text reached a bucket, the candidate is the **first text that reached the most severe bucket**. Its `Score` is that text's similarity to that bucket's example set.
  - Otherwise, it is the text with the **highest similarity to any set**, if that is ≥ `EffectiveReviewThreshold`. Otherwise there is no candidate.
  - A fast-path result has `FromFastPath = true` and no candidate.
  - `Score` must therefore stop breaking early at the ceiling, only when a candidate below-bucket search is still needed. Keep the early break when a bucket was hit.
- **Role, from spec C0d:**
  - When `GetTextsToScore` is **not** overridden, track the role of the message each text came from. Detect the override the way `_overridesGetText` does, with a delegate's `Method.DeclaringType`.
  - A deduplicated text takes the newest contributing message's role, and so does the folded first input.
  - A custom `GetTextsToScore` override or a legacy `GetText` override gives `null`.
  - Do this inside the private selection code. `SelectTextsToScore` may return `List<(string Text, ChatRole? Role)>` internally, while `TextsToEmbed` keeps returning the texts.

- [ ] **Step 1: Write the failing tests.** Use a test detector with fixed example vectors through `ExactMatchEmbeddingGenerator`, or a small generator that maps given texts to given vectors, so scores are exact.
  - `Candidate_TextReachesHighBucket_IsThatTextWithItsHighScore`: two texts. A reaches High at 0.91, and B scores 0.95 against Low only. The candidate is A with score ≈ 0.91, and `Result.Severity == HighSeverity`. This is the scenario from the builder check.
  - `Candidate_NoBucketButAboveReviewThreshold_IsBestText`: the review threshold override is 0.5, and the text scores 0.6 against Medium. The result is Clean and the candidate is that text with score ≈ 0.6.
  - `Candidate_BelowReviewThreshold_IsNull`.
  - `Candidate_FastPathMatch_FromFastPathAndNoCandidate`: SEC-01 with "ignore all previous instructions".
  - `Candidate_RoleOfTheMessageItCameFrom`: a User message and then a Tool message, where the tool text scores. The role is `ChatRole.Tool`.
  - `Candidate_FoldedText_UsesNewestContributorRole`: 18 new messages, with the scoring text in the first, folded input. The role equals the role of message index 2, the newest contributor to the folded text (Review Focus 5).
  - `Candidate_CustomGetTextsToScore_RoleIsNull`.
  - `PublicAnalyzeAsync_Unchanged`: the public overload returns the same `DetectionResult` as before for a High hit.
  - In `DetectorOptInAndThresholdTests`, add these validation cases: `ReviewThreshold_OutOfRange_Throws`, `ReviewThreshold_AboveMedium_Throws` and `ReviewThreshold_OnNonSemanticDetector_Throws`. The messages mirror the existing High/Medium ones.
- [ ] **Step 2: Run them.** `--filter-class "*ReviewCandidateTests"` and `"*DetectorOptInAndThresholdTests"`. Expected: compile failure.
- [ ] **Step 3: Implement** the interface above. In `DetectionPipeline.SafeAnalyzeAsync`, the semantic branches return `outcome.Result` and record `outcome` in a `SemanticOutcome?[] outcomes` array that `RunAsync` passes in. The rule-layer fallbacks record `FromFastPath = !result.IsClean`.
- [ ] **Step 4: Run** the full test command. Everything passes, and ComplianceEval numbers are unaffected because severities did not change.
- [ ] **Step 5: Commit.** `feat(detection): semantic detectors report a review candidate and take a ReviewThreshold`

---

### Task 3: Review criteria for every reviewable detector

**Files:**
- Modify: `src/AI.Sentinel/Detection/SemanticDetectorBase.cs`: `protected abstract string ReviewCriterion { get; }` and `internal string Criterion => ReviewCriterion;`.
- Modify: `src/AI.Sentinel/Detection/ILlmEscalatingDetector.cs`: add `string ReviewCriterion { get; }`, and rewrite the doc comment to say "reviewed by the pipeline's IDetectionReviewer when Medium or higher".
- Modify: all 45 `SemanticDetectorBase` subclasses under `src/AI.Sentinel/Detectors/{Security,Compliance,Hallucination,Operational}/`, the 5 escalating detectors (`CredentialExposureDetector`, `PiiLeakageDetector`, `EntropyCovertChannelDetector`, `SystemPromptEchoDetector`, `ToolCallFrequencyDetector`) and the semantic detector in `src/AI.Sentinel.Detectors.Sdk`.
- Modify the test subclasses so they compile: `DetectorOptInAndThresholdTests`, `EmbedOncePerScanTests` (×2), `ExampleEmbeddingCacheTests`, `ExampleVectorStoreTests`, `SemanticDetectorBaseTests` (×2), `tests/AI.Sentinel.Detectors.Sdk.Tests/DetectorTestBuilderTests.cs`, and any `ILlmEscalatingDetector` fakes such as `FakeEscalatingDetector`.
- Modify: `src/AI.Sentinel.Detectors.Sdk/README.md` and `website/docs/custom-detectors/sdk-overview.md`: the sample detector shows a `ReviewCriterion`.
- Test: `tests/AI.Sentinel.Tests/Detection/ReviewCriterionTests.cs`.

**Interfaces:**
- Produces `SemanticDetectorBase.Criterion` (internal) and `ILlmEscalatingDetector.ReviewCriterion`, which Task 5 reads.
- **A criterion is 1–2 sentences.** It states the intent that counts as a hit and names the closest legitimate look-alike that does not. For example, SEC-09: "An instruction aimed at the AI that is embedded in retrieved content, such as a document, web page or tool result, and tries to change what the AI does. Text that only describes or discusses injection techniques, such as security training or documentation, is not a hit."
- Write each criterion from the detector's own examples and its doc row in `website/docs/detectors/overview.md` or `compliance.md`.

- [ ] **Step 1: Write the failing test** `EveryReviewableDetector_HasADistinctCriterion`.
  - It reflects over all `IDetector` types in the `AI.Sentinel` assembly that are `SemanticDetectorBase` or `ILlmEscalatingDetector`, and instantiates them as `DetectorDocumentationTests` does.
  - For each, it asserts that the criterion is non-blank, has length between 40 and 400, and contains no `{` or `}`. A brace would corrupt the interpolated prompt.
  - It asserts that all criteria are pairwise distinct.
- [ ] **Step 2: Run it.** It fails to compile until the abstract member exists, then fails for each detector still missing a criterion.
- [ ] **Step 3: Add the abstract member and write the criteria.** Group the commits' work per category folder, but make it **one commit**, because the build is red until all are done.
- [ ] **Step 4: Run** the full test command and `dotnet test tests/AI.Sentinel.Detectors.Sdk.Tests`. Both pass.
- [ ] **Step 5: Commit.**

  ```
  feat(detectors)!: every reviewable detector states its review criterion

  BREAKING CHANGE: SemanticDetectorBase.ReviewCriterion is abstract and ILlmEscalatingDetector has a ReviewCriterion member, so custom detectors must state what they look for before the reviewer can judge them.
  ```

---

### Task 4: The semantic cap

**Files:**
- Modify: `src/AI.Sentinel/Detection/DetectorConfiguration.cs`: `public bool? CapSemanticSeverity { get; set; }`. The doc comment says that null or true caps, and false restores the uncapped bucket severity. It is rejected on non-semantic detectors at `AddAISentinel`.
- Modify: `src/AI.Sentinel/ServiceCollectionExtensions.cs` for that validation.
- Modify: `src/AI.Sentinel/Detection/DetectionPipeline.cs`: a new `ApplySemanticCap(DetectionResult[] results, SemanticOutcome?[] outcomes)`, run after the first `ApplySeverityClamp`, following spec C3.
- Test: `tests/AI.Sentinel.Tests/Detection/SemanticCapTests.cs`. Update existing tests that assert High or Critical from an embedding hit through a pipeline: search `tests/` for pipelines built over semantic detectors, such as `ComplianceDetectorTests` and `NamedPipelineEmbeddingTests`. Each update keeps the test's intent, either by asserting Medium or by setting `CapSemanticSeverity = false` where the test is about something else.

**Interfaces:**
- Consumes `SemanticOutcome` from Task 2.
- **Cap rule, from spec C0, D1 and C3:**
  - Applies to: results with `outcomes[i] is { FromFastPath: false }` and `Result.Severity > Medium`, where `CapSemanticSeverity != false`. Those become `Medium`, with reason `"Semantic match — capped at Medium pending review"`.
  - **Unless** the detector's configured `SeverityFloor` is above Medium, in which case the floor-applied severity stands.
  - The pipeline keeps the pre-cap "proposed" severity per index for Task 5: `Severity[] proposed`.

- [ ] **Step 1: Write the failing tests:**
  - `HighBucketHit_NoReviewer_IsMedium`
  - `Sec01MediumBucket_MappedToHigh_IsMedium`
  - `FastPathMatch_IsNotCapped`: SEC-01 stays Critical.
  - `CapSemanticSeverityFalse_KeepsBucketSeverity`
  - `SeverityFloorHigh_WinsOverCap`
  - `SeverityCapLow_StillLow`
  - `LowBucketHit_Unchanged`
  - `PublicAnalyzeAsync_StillUncapped`
  - `CapSemanticSeverity_OnRuleDetector_Throws`
- [ ] **Step 2: Run them.** `--filter-class "*SemanticCapTests"` fails.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** the full test command. Fix the tests the cap legitimately changes, as described under Files, and nothing else.
- [ ] **Step 5: Commit.**

  ```
  feat(detection)!: embedding hits alone are capped at Medium

  BREAKING CHANGE: a semantic detector's embedding result is capped at Medium unless a reviewer verdict confirms a higher severity. Regex fast-path matches keep their severity. Set DetectorConfiguration.CapSemanticSeverity = false to restore the uncapped severity for a detector in a pipeline.
  ```

---

### Task 5: The review step in the pipeline

**Files:**
- Create: `src/AI.Sentinel/Detection/ReviewLimits.cs`: `internal readonly record struct ReviewLimits(int MaxPerScan, TimeSpan Timeout) { public static ReviewLimits Default => new(4, TimeSpan.FromSeconds(5)); }`.
- Modify: `src/AI.Sentinel/Detection/DetectionPipeline.cs`.
  - The constructor parameter `IChatClient? escalationClient` becomes `IDetectionReviewer? reviewer`, with a new trailing `ReviewLimits? reviewLimits = null`.
  - Delete `EscalateAllAsync` and `EscalateAsync`, and add `ReviewAllAsync`.
- Modify: `src/AI.Sentinel/SentinelMetrics.cs`: `internal static readonly Counter<long> Reviews = Meter.CreateCounter<long>("sentinel.reviews");`.
- Modify every `new DetectionPipeline(...)` call site:
  - `src/AI.Sentinel/ServiceCollectionExtensions.cs:256` passes `null` until Task 6;
  - `src/AI.Sentinel.Mcp/McpPipelineFactory.cs:86` passes `reviewer: null` until Task 8;
  - every test listed by `git grep -n "escalationClient:" tests`, which become `reviewer:`. Tests that passed a chat client wrap it: `reviewer: new LlmJudgeReviewer(client)`.
- Test: `tests/AI.Sentinel.Tests/Detection/ReviewStepTests.cs`. Move the escalation behaviour tests from `DetectionPipelineTests` and `EffectiveActionTests` here, rewritten against a `FakeReviewer : IDetectionReviewer` that records requests and returns scripted verdicts or delays.

**Interfaces:**
- Consumes: `SemanticOutcome` and `ReviewCandidate` (Task 2), `Criterion` and `ILlmEscalatingDetector.ReviewCriterion` (Task 3), and the `proposed` severities (Task 4).
- **Candidates, from spec D2 and C0:**
  - A semantic detector with `outcomes[i]` not from the fast path, a non-null `Candidate`, and either proposed ≥ Medium or a candidate from the review band.
  - An `ILlmEscalatingDetector` with proposed ≥ Medium. Its text is the newest message's `SentinelContext.MessageText`, its role is that message's role, and `Score` is null.
  - A detector whose configured `SeverityCap` is below Medium is a candidate only for below-bucket candidates.
- **Ranking, from spec D4:**
  - proposed severity, descending;
  - then rule-based before semantic at equal severity;
  - then `Score`, descending.

  Take the first `MaxPerScan`. The rest are counted `over_budget`.
- **Request fields:**
  - `ProposedSeverity` = proposed, or `None` for a band candidate below Low.
  - `MaximumSeverity` = `MaximumBucketSeverity`, limited by a configured `SeverityCap`. For rule-based detectors it is `Critical`, limited by `SeverityCap`.
- **Applying a verdict, from spec C2:**

  | Verdict | Result | `outcome` tag |
  |---|---|---|
  | `null` | shown result, unchanged | `no_verdict` |
  | > maximum | clamped to maximum, then as below | |
  | `None` | `DetectionResult.Clean` | `cleared` |
  | == proposed | proposed severity, i.e. uncapped | `confirmed` |
  | > proposed | that severity | `raised` |
  | < proposed, not None | that severity | `lowered` |

  The reason is `$"Reviewed: {outcome} — {Sanitise(verdict.Reason)}"`. The sanitiser collapses whitespace and control characters and truncates to 200 characters, so reuse or generalise `SemanticDetectorBase.Sanitise`.
- **Execution:**
  - Run all selected reviews concurrently.
  - Each review is `reviewer.ReviewAsync(request, linkedToken).AsTask().WaitAsync(limits.Timeout, ct)`, inside a try block that also catches synchronous throws.
  - A `TimeoutException` gives `timed_out`. Any other exception, while `!ct.IsCancellationRequested`, gives `failed`. `OperationCanceledException` with `ct` cancelled is rethrown.
  - On failure, timeout or over budget the shown result stands.
  - After all reviews, `ApplySeverityClamp` runs again, then `ApplyActionOverrides`, as today.
  - A scan with ≥ 1 `failed`/`timed_out` logs **one** warning: "AI.Sentinel: {n} of {m} reviews failed or timed out; those detections keep their capped severity." It also invokes `_onDetectorFailure` once with the same text.
  - Every reviewed or over-budget candidate adds 1 to `SentinelMetrics.Reviews` with its `outcome` and `detector` tags.
- With `reviewer == null` or `MaxPerScan == 0`, no candidate is collected and no metric is emitted.

- [ ] **Step 1: Write the failing tests** in `ReviewStepTests`:
  - `Review_ConfirmsHighBucket_LiftsCapToBucketSeverity`: SEC-01-style mapping, where a Medium bucket maps to High and the verdict High gives High.
  - `Review_RaisesBandCandidate_ToMedium`
  - `Review_VerdictAboveMaximum_IsClamped`
  - `Review_None_Clears`
  - `Review_NullVerdict_KeepsCappedResult`
  - `Review_FastPathMatch_NotSentToReviewer`
  - `Review_RuleBasedEscalatingDetector_UsesNewestMessageAndCriterion`: this ports today's #434 tool-result test.
  - `Review_BudgetOfTwo_ReviewsTopTwoByRanking_RestOverBudget`: 4 candidates with distinct proposed severities and scores. The reviewer sees exactly the top two, and the metric records 2 × `over_budget`. Use a `MeterListener` as the existing telemetry tests do.
  - `Review_RunsConcurrently`: two reviewers that each wait on a shared `TaskCompletionSource` released only when both have started. The scan completes.
  - `Review_ReviewerIgnoresToken_TimesOutAndKeepsCappedResult`: the reviewer awaits `Task.Delay(Timeout.Infinite)` without the token, and `Timeout` is 50 ms (Review Focus 1).
  - `Review_CallerCancels_Propagates`: no warning is logged (Review Focus 2).
  - `Review_ReviewerThrowsSynchronously_KeepsCappedResult` (Review Focus 3).
  - `Review_ReasonIsSanitisedAndTruncated`: a reason of `"a\nb\r\n" + new string('x', 10_000)` gives a single line of ≤ 200 characters after the prefix (Review Focus 4).
  - `Review_TwoFailures_OneWarningOneFailureCallback`
  - `Review_SeverityCapLow_AtOrAboveMediumNotACandidate_BandCandidateLimitedToCap`
  - `Review_MaxPerScanZero_NoReviews`
- [ ] **Step 2: Run them.** `--filter-class "*ReviewStepTests"` fails.
- [ ] **Step 3: Implement** the review step, and the call-site renames under Files.
- [ ] **Step 4: Run** the full test command, and `dotnet build` for the whole solution, because the Mcp project changed. Both are green.
- [ ] **Step 5: Commit.** `feat(detection): one review step for semantic and rule-based detections, with a budget and timeout`

---

### Task 6: Options, DI wiring and the unreviewed-detection warning

**Files:**
- Modify: `src/AI.Sentinel/SentinelOptions.cs`:
  - `public IDetectionReviewer? Reviewer { get; set; }`
  - `public int MaxReviewsPerScan { get; set; } = 4;`, rejected when negative, with the attribute style already used, such as `[GreaterThan]` or the repo's range validation.
  - `public TimeSpan ReviewTimeout { get; set; } = TimeSpan.FromSeconds(5);` with `[PositiveTimeSpan]`.
  - `EscalationClient` stays, and its doc says it is shorthand for `Reviewer = new LlmJudgeReviewer(client)`.
- Modify: `src/AI.Sentinel/ServiceCollectionExtensions.cs`:
  - `BuildDetectionPipeline` passes `opts.Reviewer ?? (opts.EscalationClient is { } c ? new LlmJudgeReviewer(c) : null)` and `new ReviewLimits(opts.MaxReviewsPerScan, opts.ReviewTimeout)`.
  - `AddAISentinel` throws `ArgumentException` when both `Reviewer` and `EscalationClient` are set: "AI.Sentinel: set either Reviewer or EscalationClient, not both. EscalationClient is shorthand for Reviewer = new LlmJudgeReviewer(client)."
  - Named pipelines use their own options' values; there is no inheritance, as with `EscalationClient` today.
  - Add `public static string? DescribeUnreviewedSemanticDetection(this IServiceProvider sp)` and `DescribeUnreviewedSemanticDetection(SentinelOptions options, IEnumerable<IDetector> detectors)`, mirroring `DescribeInertSemanticDetection`, plus a `WarnIfSemanticDetectionUnreviewed` logged where `WarnIfSemanticDetectionInert` is logged. The message is non-null only when a generator resolves, no reviewer resolves, and at least one enabled semantic detector has the cap on:

    "AI.Sentinel: {n} semantic detector(s) are capped at Medium because no reviewer is configured. Set SentinelOptions.Reviewer or EscalationClient, or SENTINEL_REVIEW_* for the CLI tools, to let a reviewer confirm High and Critical detections."

    The named-pipeline variant includes the pipeline name, as the inert warning does.
- Modify: `README.md` lines 181–182 and 270, plus `website/docs/detectors/overview.md` and `website/docs/configuration/named-pipelines.md`. Describe the review step, the cap, the opt-out, the review threshold, the budget and timeout, and `EscalationClient` as shorthand. Remove the "only Medium or above" and "cannot create one" claims where they are no longer true for semantic detectors.
- Test: `tests/AI.Sentinel.Tests/SentinelOptionsTests.cs`, `ServiceCollectionExtensionsTests.cs` and `NamedPipelineTests.cs`.

**Interfaces:**
- Produces: `SentinelOptions.Reviewer`, `MaxReviewsPerScan` and `ReviewTimeout`, and both `DescribeUnreviewedSemanticDetection` overloads, which Task 8 calls.

- [ ] **Step 1: Write the failing tests:**
  - `EscalationClient_BecomesLlmJudgeReviewer`: a scan through the built pipeline sends the request to that client.
  - `ReviewerAndEscalationClientBoth_Throws`
  - `MaxReviewsPerScanNegative_Throws`
  - `ReviewTimeoutZero_Throws`
  - `NamedPipeline_UsesItsOwnReviewer`
  - `UnreviewedWarning_GeneratorNoReviewer_Logged`
  - `UnreviewedWarning_NoGenerator_Null`
  - `UnreviewedWarning_ReviewerSet_Null`
  - `UnreviewedWarning_AllCapsOff_Null`
- [ ] **Step 2: Run them.** They fail.
- [ ] **Step 3: Implement**, and update the docs listed under Files.
- [ ] **Step 4: Run** the full test command. It passes.
- [ ] **Step 5: Commit.** `feat(options): Reviewer, MaxReviewsPerScan and ReviewTimeout, with a warning when semantic detections go unreviewed`

---

### Task 7: OpenAI-compatible chat client and `SentinelReviewSetup`

**Files:**
- Create: `src/AI.Sentinel/Review/OpenAICompatibleChatClient.cs`: `public sealed class OpenAICompatibleChatClient : IChatClient`, modelled on `src/AI.Sentinel/Embeddings/OpenAICompatibleEmbeddingGenerator.cs`, with the same constructor shape, `HttpClient` ownership, bearer key and error handling.
  - It POSTs `{"model":…,"messages":[{"role":…,"content":…}],"temperature":0}` to the full endpoint URL and reads `choices[0].message.content`.
  - `GetStreamingResponseAsync` throws `NotSupportedException`.
- Create: `src/AI.Sentinel/Review/ReviewJsonContext.cs`: a source-generated `JsonSerializerContext` for the request and response records.
- Create: `src/AI.Sentinel/Review/SentinelReviewSetup.cs`: `public sealed class SentinelReviewSetup : IDisposable`, with `IDetectionReviewer Reviewer`, `int? MaxReviewsPerScan`, `TimeSpan? ReviewTimeout` and `public static SentinelReviewSetup? TryCreateFromEnvironment(IReadOnlyDictionary<string, string?> environment, out string? error)`, mirroring `SentinelEmbeddingSetup.TryCreateFromEnvironment`.
  - No `SENTINEL_REVIEW_ENDPOINT` gives null with no error.
  - An endpoint without a model, a non-absolute or non-http(s) URL, a non-integer or negative `MAX_PER_SCAN`, or a non-positive `TIMEOUT_MS` gives null with an error that names the variable.
- Test: `tests/AI.Sentinel.Tests/Review/OpenAICompatibleChatClientTests.cs` and `SentinelReviewSetupTests.cs`. Follow `OpenAICompatibleEmbeddingGeneratorTests` and `SentinelEmbeddingSetupTests`: a stub `HttpMessageHandler`, and an environment dictionary.

**Interfaces:**
- Produces `SentinelReviewSetup.TryCreateFromEnvironment`, `.Reviewer`, `.MaxReviewsPerScan` and `.ReviewTimeout`, all used by Task 8.

- [ ] **Step 1: Write the failing tests.**
  - Request: the body has the model, both messages with roles, and `temperature` 0, plus the bearer header when a key is set and no header when it is not.
  - Response: the content is parsed. A non-2xx status throws `HttpRequestException` with the status in the message. Missing `choices` throws `InvalidDataException`.
  - Setup: a valid configuration gives a reviewer that is an `LlmJudgeReviewer`. Add one test per malformed variable that asserts the variable name is in `error`.
- [ ] **Step 2: Run them.** They fail.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** the full test command, then the AOT probe build: `dotnet publish tests/AI.Sentinel.Aot.Probe -c Release`, or whichever command `DetectorRegistrationTrimTests` uses. It shows no new trim or AOT warnings.
- [ ] **Step 5: Commit.** `feat(review): OpenAI-compatible chat client and SENTINEL_REVIEW_* setup for hosts without DI configuration`

---

### Task 8: Wire the reviewer into the CLI hosts

**Files:**
- Modify: `src/AI.Sentinel.ClaudeCode.Cli/Program.cs` and `src/AI.Sentinel.Copilot.Cli/Program.cs`.
  - In `EvaluateAsync`, create `SentinelReviewSetup` next to the embedding setup, reading `SENTINEL_REVIEW_*` in the same `ReadEnvironment` pass, and write a setup error to stderr.
  - `BuildProvider` gets an `IDetectionReviewer? reviewer, ReviewLimits limits` pair and sets `opts.Reviewer`, `opts.MaxReviewsPerScan` and `opts.ReviewTimeout`. The default timeout is **3 s** when `SENTINEL_REVIEW_TIMEOUT_MS` is unset.
  - The semantic warning shown on Allow combines `DescribeInertSemanticDetection()` with `DescribeUnreviewedSemanticDetection()`, under the existing `SuppressSemanticWarning` gate.
- Modify: `src/AI.Sentinel.Mcp/McpProxy.cs` and `McpPipelineFactory.cs`: the same, passing `reviewer` and `ReviewLimits` into `Assemble`, with the 5 s default, and the unreviewed warning alongside `inertSemanticWarning`.
- Modify: `src/AI.Sentinel.Cli/ScanCommand.cs` and `ForensicsPipelineFactory.cs`: `Build` gets `IDetectionReviewer? reviewer = null` and `ReviewLimits? reviewLimits = null`, and `ScanCommand` reads `SENTINEL_REVIEW_*` the way it reads the embedding variables. The 5 s default applies.
- Modify: `website/docs/integrations/claude-code.md`, `copilot.md` and `mcp-proxy.md`, plus the README's environment variable table, if there is one next to `SENTINEL_EMBEDDING_*`. List the five variables and the hook timeout default.
- Test: the existing host test folders `tests/AI.Sentinel.Tests/ClaudeCode`, `Copilot`, `Mcp` and `Cli`.

**Interfaces:**
- Consumes: Task 6's options and warning, and Task 7's setup.

- [ ] **Step 1: Write the failing tests**, one per host:
  - `ClaudeCodeHook_WithReviewer_ConfirmedSemanticHighBlocks`: through `BuildProvider` with a fake reviewer that returns High, a fake generator and a semantic High hit. The decision is Block.
  - `ClaudeCodeHook_NoReviewer_SemanticHighWarnsOnly`
  - `ClaudeCodeHook_ReviewTimeoutDefaultsTo3s`
  - `CopilotHook_WithReviewer_ConfirmedSemanticHighBlocks`
  - `McpProxy_WithReviewer_ConfirmedSemanticHighBlocks`
  - `ScanCommand_ReadsReviewEnvironment`
  - `BadReviewSetting_ReportedOnStderrByName`
- [ ] **Step 2: Run them.** They fail.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** the full test command and a full solution build. Both are green.
- [ ] **Step 5: Commit.** `feat(hosts): hook CLIs, MCP proxy and scan read SENTINEL_REVIEW_* so confirmed semantic detections can block`

---

### Task 9: ComplianceEval split field

**Files:**
- Modify: `tools/AI.Sentinel.ComplianceEval/Phrase.cs`: add `string Split`, read from the required `split` property, and `bool IsHeldOut`. A missing or unknown value throws `InvalidDataException` with the phrase text.
- Modify: `tests/AI.Sentinel.Tests/Detectors/Compliance/compliance-phrases.json`, `tools/AI.Sentinel.ComplianceEval/security-phrases.json` and `everyday-prompts.json`: add `"split": "fit"` to every existing entry, as a mechanical edit with no other change. Update each file's `description` to explain `split`.
- Modify: the unit tests that guard these files. Find them with `git grep -ln "compliance-phrases.json\|security-phrases.json" tests`, and assert that every entry has `split` ∈ {`fit`, `heldout`}.

- [ ] **Step 1: Write the failing guard assertion** in the existing guard test, e.g. `EveryPhrase_HasAValidSplit`.
- [ ] **Step 2: Run it.** It fails.
- [ ] **Step 3: Add the field** to all entries with a small script, `jq` or a Python one-off, so formatting is preserved. Then update `Phrase.Load`.
- [ ] **Step 4: Run** the full test command, and `dotnet run --project tools/AI.Sentinel.ComplianceEval -- --model all-MiniLM-L6-v2`. It produces the same report as before, and the exit code is unchanged.
- [ ] **Step 5: Commit.** `test(eval): every phrase is marked fit or heldout`

---

### Task 10: ComplianceEval three-configuration report

**Files:**
- Create: `tools/AI.Sentinel.ComplianceEval/ReviewEvaluation.cs`.
  - For each held-out phrase and each configuration, it runs the detector through an internal `DetectionPipeline` built over that single detector: `new DetectionPipeline([detector], configurations, reviewer, …, embeddingScope)`.
  - Configuration 1 sets `CapSemanticSeverity = false` with no reviewer. Configuration 2 uses the default, capped and without a reviewer. Configuration 3 is capped with `LlmJudgeReviewer`.
  - It records the severity and the wall time of configuration 3 minus that of configuration 2 per phrase.
- Modify: `tools/AI.Sentinel.ComplianceEval/Program.cs`:
  - add the option `--judge-model <id>`, defaulting to the newest Sonnet model ID at build time, and confirm the ID with the claude-api skill;
  - read `ANTHROPIC_API_KEY`, and build the judge as `new OpenAICompatibleChatClient(new Uri("https://api.anthropic.com/v1/chat/completions"), model, key)`;
  - without a key, skip configuration 3 and write "Judge columns skipped: ANTHROPIC_API_KEY not set." in the report;
  - append a "Held-out review" section per detector, with columns: config, positives ≥ High, positives ≥ Medium, benign ≥ High, benign ≥ Medium, p50 added ms, p95 added ms, reviews per scan and share over budget;
  - add the configuration-3 line "a legitimate request reached High" to the report without failing. The exit-code rule stays on configuration 1, as today's direct path, per spec C0f.
- Modify: `docs/superpowers/evaluations/2026-10-17-compliance-detectors.md`. Add a "4.0 second-stage review" section that explains the three configurations and the split. Because every phrase is still `fit` in this PR, the held-out tables are empty and the section says so. #432 and #433 add held-out phrases.
- Test: `tests/AI.Sentinel.Tests` has no ComplianceEval project reference. If one exists, add a test for the percentile helper. Otherwise keep the helper trivial and verify it by running the tool.

- [ ] **Step 1: Add the percentile and table helpers** with a unit test, if the tool is test-referenced, for `Percentile([1,2,3,4], 0.5) == 2.5` and `Percentile([], 0.95) == 0`.
- [ ] **Step 2: Implement `ReviewEvaluation`** and the `Program` changes.
- [ ] **Step 3: Run** `dotnet run --project tools/AI.Sentinel.ComplianceEval -- --model all-MiniLM-L6-v2` without a key. The report contains the held-out section with the "skipped" line, and the exit code matches Task 9's run. If `ANTHROPIC_API_KEY` is available, run once with it and check that the judge columns appear.
- [ ] **Step 4: Run** the full test command. It passes.
- [ ] **Step 5: Commit.** `feat(eval): report held-out recall, false positives and review latency for embeddings, capped and judged`

---

## After the last task

- Code review of the whole branch: the superpowers:requesting-code-review flow, then `pre-push-review`. Fix every finding in this branch, nits included.
- `git push -u origin feat/511-second-stage-review`, then open the PR. The body says it closes nothing and is part of #511. Leave #511 open until #432 and #433 land, or close it if Marcel prefers. It has no Claude signature.
- After merge, confirm that the release-please PR lists the `feat!` commits and proposes 4.0.0.
