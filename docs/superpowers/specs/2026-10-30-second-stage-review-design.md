# Second-stage review for detections (#511, then #432 and #433)

## Why

Embedding similarity measures topic, not intent. The evaluations show it from both sides:

- **Misses.** None of the 18 paraphrased SEC-01/05/09 positives reach any bucket at the default thresholds (#432). CMP-03 catches 1 of 7 positives (#433).
- **False alarms.** On MiniLM, a benign SEC-09 text ("a training slide on how attackers hide instructions in documents") scores above every SEC-09 positive. Raising CMP-03's recall pushed legitimate fairness audits to High.

No threshold fixes both, so embeddings cannot have the last word. They stay as cheap triage, and a second stage decides. Today that second stage, `ILlmEscalatingDetector` plus `SentinelOptions.EscalationClient`, cannot do the job:

1. None of the 45 `SemanticDetectorBase` detectors can escalate.
2. Escalation only fires at Medium or above, so it can remove false positives but never recover a miss.
3. It is hard-wired to `IChatClient`, so a decision model (#304, SecJev on ZeroAlloc.Jev) has no slot.
4. It sends the newest message to the judge, not the text the detector scored.

#515 (Wave 1, in 3.9.0) already fixed the verdict parsing: JSON `severity`, `None`/`Low` as downgrades, a fenced data boundary, and Floor/Cap re-applied after escalation. That stays.

**No deployment is live yet**, so Marcel chose to change the defaults now rather than add the new behaviour as an opt-in.

## Goals

1. **Semantic hits are triage.** Without a second-stage verdict, a semantic detector's result is Medium at most.
2. **One pluggable second stage**, `IDetectionReviewer`, used by both semantic and rule-based detectors. A built-in LLM judge implements it. #304 adds a decision-model reviewer later without changing the interface.
3. **Near misses get a second look.** A per-detector review threshold below the Low bucket makes texts that did not reach a bucket candidates for review.
4. **Bounded cost and latency** per scan.
5. **Measured.** ComplianceEval reports recall, false positives and added latency on a held-out split for three configurations: embeddings alone (today), embeddings capped, and embeddings plus the judge.
6. **#432 and #433 fixed** on top of this, by tuning examples and thresholds on fit data and setting review thresholds, with the numbers recorded.

## Non-goals

- The decision-model reviewer itself (#304). This change only has to make it fit.
- Contrastive scoring, meaning counter-example sets in `SemanticDetectorBase` (Marcel chose not to do it for CMP-03).
- Resolving a reviewer from the DI container, such as `WithReviewerFromServices`. A pipeline sets it on `SentinelOptions`.
- Reviewing results of detectors that are neither semantic nor `ILlmEscalatingDetector`.

## Anti-goals

These would make the change a failure even if the tests pass:

- **An embedding score alone produces High or Critical** in a pipeline that has not opted the detector out.
- **A reviewer failure makes a result worse than the capped result.** For example: a timeout turns a capped Medium into Clean, or restores an uncapped Critical.
- **Unbounded reviewer calls.** For example, 45 judge calls on one message.
- **Untrusted text reaches the judge as instructions.** The #515 fencing must hold for every review.
- **Tuning on the held-out set.** Any value chosen by looking at held-out results invalidates the reported numbers.
- **A regex fast-path match gets capped.** Those are rule matches with no innocent reading, so they keep their severity.

## Decided by Marcel

### D1. Semantic hits are capped, by default, everywhere

- A semantic detector's result from embedding similarity is **capped at Medium** unless a reviewer verdict says otherwise.
- The cap applies to the **final severity**, not the bucket. Some detectors map buckets upward: SEC-01 maps its Medium bucket to High and its High bucket to Critical. Without a verdict, both become Medium.
- **Fast-path regex matches are not capped.** They keep `FastPathSeverity`.
- The cap is the **default for every pipeline**. A detector can opt out per pipeline, which restores today's uncapped severity (see C1).
- A pipeline with **no reviewer** and at least one enabled semantic detector logs **one warning when the pipeline is built**. The warning says that semantic detections are capped at Medium, and that a reviewer is needed to reach High or Critical.

### D2. Trigger band: a per-detector review threshold

- `SemanticDetectorBase` gets `protected virtual float ReviewThreshold`, defaulting to `LowThreshold`.
- `DetectorConfiguration` gets `float? ReviewThreshold`. It is validated like the other thresholds: in (0, 1], not above the effective Medium threshold, and rejected on non-semantic detectors at `AddAISentinel`.
- **Review candidates**, when a reviewer is configured:
  - every semantic result at Medium or above, before the cap;
  - every semantic text whose best similarity to *any* example set is at or above the effective `ReviewThreshold`, including texts that reached Low or no bucket at all;
  - every `ILlmEscalatingDetector` result at Medium or above, as today.
- ComplianceEval sets the shipped `ReviewThreshold` per detector for the detectors in #432 and #433 (D6). The others keep the default.

### D3. The provider: `IDetectionReviewer`

A public interface in `AI.Sentinel.Detection`:

```csharp
public interface IDetectionReviewer
{
    ValueTask<ReviewVerdict> ReviewAsync(ReviewRequest request, CancellationToken cancellationToken);
}

public sealed record ReviewRequest(
    DetectorId DetectorId,
    string Criterion,          // what the detector looks for, see below
    string Text,               // the text that scored, not the whole scan
    ChatRole Role,             // the role of the message the text came from
    float? Score,              // best similarity; null for rule-based detectors
    Severity ProposedSeverity, // the uncapped severity, or None for a below-Low candidate
    Severity MaximumSeverity); // the highest severity a verdict may set for this detector

public sealed record ReviewVerdict(Severity? Severity, string Reason)
{
    public static ReviewVerdict None { get; } = new(null, string.Empty);   // no verdict
}
```

- **The criterion:**
  - `SemanticDetectorBase` gets `protected abstract string ReviewCriterion`, and all 45 detectors write their own: a one- or two-sentence statement of the intent that counts as a hit and of the look-alikes that do not.
  - The rule-based escalating detectors get a criterion too, through a new member on `ILlmEscalatingDetector`. The detectors are CredentialExposure, PiiLeakage, EntropyCovertChannel, SystemPromptEcho and ToolCallFrequency.
- **Making it abstract is a breaking change** for third-party detectors built on `SemanticDetectorBase`. That is accepted, see Release.
- **`LlmJudgeReviewer`** is the built-in implementation, wrapping an `IChatClient`.
  - It keeps #515's prompt hardening: a per-call random boundary, a "treat as data" instruction, a JSON-only answer and the tolerant parser.
  - The prompt changes from "a rule-based detector flagged" to the criterion plus the proposed severity, and asks whether the text matches the criterion and at what severity.
  - The text is truncated to the last 64 KiB, as today.
- **`SentinelOptions.Reviewer`** is a new `IDetectionReviewer?` setting.
  - `SentinelOptions.EscalationClient` stays as shorthand: setting it means `Reviewer = new LlmJudgeReviewer(client)`.
  - Setting both throws at `AddAISentinel`.
  - Named pipelines inherit `Reviewer` the way they inherit `EscalationClient` today.
- **One second stage:** `EscalateAllAsync` and `EscalateAsync` are replaced by the review step. Rule-based escalating detectors go through the same reviewer.
  - Their text stays the newest message's detection text, as today, because they do not report which text matched.
  - Their `MaximumSeverity` is Critical, as today.

### D4. Budget, latency and failures

- `SentinelOptions.MaxReviewsPerScan` defaults to 4. A value of 0 disables review.
- Candidates are ranked by uncapped severity, highest first. Ties are broken by score, highest first, and rule-based candidates without a score come before semantic ones of the same severity. Within each detector, only its best candidate text counts, so one detector takes at most one review.
- The top `MaxReviewsPerScan` candidates are reviewed **concurrently**, each under `SentinelOptions.ReviewTimeout`, default 5 s. The timeout is a linked token, and the caller's cancellation still cancels the scan.
- **What happens without a verdict:** a candidate over budget, timed out, thrown or unparseable keeps its **capped result**. That is Medium at most, Low if it was Low, and Clean if it was below Low.
- Each such case is counted on a new `sentinel.reviews` counter, tagged `outcome` = `confirmed|raised|lowered|cleared|no_verdict|failed|timed_out|over_budget` and `detector`. A scan with any `failed` or `timed_out` review logs **one** warning.
- A reviewer failure never makes a result worse than the capped result (anti-goal).

### D5. Evaluation

- Every phrase in `compliance-phrases.json`, `security-phrases.json` and `everyday-prompts.json` gets a `split` field, `fit` or `heldout`. `Phrase` reads it, and the unit tests that guard the files require it.
- The existing phrases become `fit`. New phrases written for this change are split roughly 50/50 per detector and per label, and are assigned before any scoring.
- `security-phrases.json` grows to about **15 positives per detector** for SEC-01, SEC-05 and SEC-09. New benign texts must include tool outputs and documents that *discuss* injection, jailbreaks and prompt leaking, because these are the hard negatives.
- Examples, High/Medium thresholds and `ReviewThreshold`s are tuned on `fit` only. `heldout` is scored and reported, and is never used for a tuning decision.
- **The judge in the eval** is `LlmJudgeReviewer` on a Claude model through `ANTHROPIC_API_KEY`, with the model passed as an option and the newest Sonnet as the default. Without a key, the judge columns are skipped and the report says so.
- **Report per detector**, on the held-out split, for three configurations:
  1. embeddings alone, uncapped (today's behaviour);
  2. embeddings capped;
  3. embeddings plus the judge.

  The numbers are recall at High or above and at Medium or above, false positives at each level, and p50/p95 latency added by review. The report also gives reviews per scan and the share of candidates over budget.
- The exit code rule "a legitimate request reached High" is evaluated on configuration 1, uncapped embeddings, matching C0f. On configuration 3 it is reported but does not fail, because judge output is not deterministic.

### D6. #432 and #433: reviewer plus tuning

- **#432**, for SEC-01, SEC-05 and SEC-09:
  - refine the High and Medium examples toward intent, and drop examples that pull benign security talk;
  - set High and Medium with the existing rule on `fit` data only: High 0.05 above the closest benign text, Medium 0.02 above it;
  - set `ReviewThreshold` low enough that `fit` paraphrases become candidates, while benign candidates per scan stay within budget on the everyday set.
- **#433**, for CMP-03: the same steps.
- Record the shipped values and the held-out numbers in `docs/superpowers/evaluations/2026-10-17-compliance-detectors.md`, and list them in the release notes as behaviour changes.

### D7. The CLI hosts get a reviewer from environment variables, in PR 1

The hook CLIs (`AI.Sentinel.ClaudeCode.Cli`, `AI.Sentinel.Copilot.Cli`), the MCP proxy (`AI.Sentinel.Mcp`) and the forensics CLI (`AI.Sentinel.Cli`) build their own pipelines and today pass no escalation client. Without a reviewer the cap would leave them unable to block on a semantic detection, so 4.0.0 must not ship without this:

- **`SentinelReviewSetup`** sits in `src/AI.Sentinel/Review/` (or next to `SentinelEmbeddingSetup`) and mirrors it. It reads:
  - `SENTINEL_REVIEW_ENDPOINT`: the full chat-completions URL. Required to enable review.
  - `SENTINEL_REVIEW_MODEL`: required when the endpoint is set.
  - `SENTINEL_REVIEW_API_KEY`: optional, for local servers.
  - `SENTINEL_REVIEW_MAX_PER_SCAN`: overrides `MaxReviewsPerScan`.
  - `SENTINEL_REVIEW_TIMEOUT_MS`: overrides `ReviewTimeout`.

  A malformed setting is reported by name, not ignored, like the embedding setup.
- **A hand-written, AOT-safe OpenAI-compatible chat client** (`IChatClient`, source-generated JSON) goes behind `LlmJudgeReviewer`, like `OpenAICompatibleEmbeddingGenerator`. It covers Anthropic's OpenAI-compatible endpoint, Ollama and other hosts. No new package dependency in the AOT CLIs.
- All four hosts are wired up the way they wire `SENTINEL_EMBEDDING_*`. The hook CLIs default `ReviewTimeout` to **3 s**, because a hook is a process per call.
- The hosts' README and docs list the new variables.

## Builder's calls (Claude's, flagged for review)

- **C0. Which number is which: one rule for the whole pipeline.** These definitions settle candidacy, ranking, the request fields and the metric outcome:
  - The **bucket severity** is what scoring produced.
  - The **proposed severity** is the bucket severity after the configured Floor/Cap from `DetectorConfiguration`.
  - The **shown severity** is the proposed severity after the semantic cap, so at most Medium, or the configured floor when that is higher.
  - **`MaximumSeverity`** is the detector's highest bucket severity, limited by a configured `SeverityCap`.
  - Candidacy and ranking use the proposed severity. Without a verdict the result is the shown severity.
  - **A configured `SeverityFloor` above Medium raises the cap level to the floor; it does not remove the cap.** The shown severity is min(proposed, max(Medium, floor)), so a Critical bucket with a High floor shows High until a verdict confirms it. The floor is an explicit choice by whoever configured the pipeline, but it does not tell how sure the embedding is. The anti-goal is about the default behaviour.
  - A configured `SeverityCap` below Medium makes results at or above Medium non-candidates. Below-bucket candidates are still reviewed, and the verdict is limited to the cap.
- **C0b. Fast-path matches are not review candidates.** They keep their severity, are never sent to the reviewer and use no budget. A judge must not be able to clear a textbook injection.
- **C0c. The candidate text** is the text that produced the bucket result: the first text that reached the most severe bucket. Only when no text reached a bucket is it the text with the highest similarity to any example set, measured against `ReviewThreshold`. Ranking across detectors uses that text's score, meaning its similarity to the set of the bucket it reached.
- **C0d. Role.** `ReviewRequest.Role` is `ChatRole?`.
  - The default `GetTextsToScore` path tracks the role of the newest message that contributed the text.
  - Folded texts, which join more than 16 texts, use the newest contributor's role.
  - A custom `GetTextsToScore` override gives null.
  - The public override signature does not change.
- **C0e. Startup warning.** It is logged only when the pipeline has a resolved embedding scope and at least one enabled semantic detector with the cap on. A per-process host (hook CLI) logs it to its normal diagnostic sink, like the embedding-setup messages, not to stdout.
- **C0f. Eval gate and path.**
  - The exit-code rule "a legitimate request reached High" stays on **configuration 1**, uncapped embeddings, because it guards the false alarms that #432 and #433 are about.
  - Configurations 2 and 3 run through an internal pipeline-level path, `InternalsVisibleTo` the eval tool. The tool's direct `detector.AnalyzeAsync` calls remain for configuration 1.
- **C1. The opt-out** is per pipeline, per detector: `DetectorConfiguration.CapSemanticSeverity`, a `bool?` that defaults to true. Setting it to false restores the uncapped bucket severity, so the detector also needs no review to reach High. This matches how thresholds and Floor/Cap are configured today. There is no detector-level virtual, because a detector author should not be able to bypass the cap for users.
- **C2. What a verdict may set:**
  - any severity from None up to `MaximumSeverity`. For a semantic detector, that is the highest of its High, Medium and Low bucket severities: Critical for SEC-01, High for a detector with default mappings;
  - a verdict above the maximum is clamped to it;
  - a verdict equal to the proposed severity returns the uncapped result, which is how a confirmation lifts the cap.
- **C3. Order of operations,** using the terms of C0:
  1. detectors run, giving bucket severities;
  2. Floor/Cap from `DetectorConfiguration`, giving proposed severities;
  3. the semantic cap, giving shown severities. A configured Floor above Medium raises the cap level to the floor;
  4. review on the candidates, ranked by proposed severity;
  5. Floor/Cap again;
  6. action overrides.

- **C4. Scoring output.** `SemanticDetectorBase`'s internal scoring path returns, next to the `DetectionResult`, an internal review candidate:
  - the candidate text, chosen as in C0c;
  - its score and its role, as in C0d;
  - whether the result came from the fast path, which is never capped.

  The public `AnalyzeAsync(ctx, ct)` is unchanged and uncapped. The cap and review are pipeline behaviour, so direct callers such as SDK tests see bucket severities as before.
- **C5. The reason string** of a reviewed result keeps the detector's own reason, then names the outcome and keeps the reviewer's reason, sanitised like rule-match reasons and capped at 200 characters: "<detector reason> — Reviewed: confirmed — <reason>". For a capped semantic result the detector's reason is the bucket reason from before the cap; a text that reached no bucket has none, and an empty reviewer reason drops the last part. A capped result says "Semantic match — capped at Medium pending review" so the dashboard and audit show why.
- **C6. Delivery** is three PRs from fresh `origin/main` branches, in this order:
  1. #511: the reviewer, cap, band, metrics, CLI host reviewer (D7), eval split and the three-configuration report, with the existing phrases all marked `fit`;
  2. #432;
  3. #433.
- **C7. Release.** PR 1 is `feat!`, because the default severities change and `ReviewCriterion` is a new abstract member. That makes it 4.0.0. The migration notes cover the cap and how to opt out, `EscalationClient` now being shorthand, the abstract `ReviewCriterion` and the `SENTINEL_REVIEW_*` variables for the CLI hosts.

## Left to the builder

- The exact prompt wording of `LlmJudgeReviewer`, within D3.
- The internal type names for the review candidate and the review step.
- Whether `ReviewRequest` carries the scan's `SentinelContext` for future reviewers. Leave it out unless #304 needs it.
- The default eval judge model ID, which must be the newest Sonnet at build time.

## Files in play

- `src/AI.Sentinel/Detection/DetectionPipeline.cs`: review step, cap, ordering and the startup warning.
- `src/AI.Sentinel/Detection/SemanticDetectorBase.cs`: `ReviewThreshold`, `ReviewCriterion`, candidate output.
- `src/AI.Sentinel/Detection/DetectorConfiguration.cs`: `ReviewThreshold`, `CapSemanticSeverity`.
- `src/AI.Sentinel/Detection/ILlmEscalatingDetector.cs`: criterion member.
- New: `IDetectionReviewer.cs`, `ReviewRequest`/`ReviewVerdict`, `LlmJudgeReviewer.cs`.
- `src/AI.Sentinel/SentinelOptions.cs`, `ServiceCollectionExtensions.cs`: `Reviewer`, `MaxReviewsPerScan`, `ReviewTimeout`, validation.
- `src/AI.Sentinel/SentinelMetrics.cs`: `sentinel.reviews`.
- All 45 semantic detectors and 5 escalating detectors: criteria.
- `tools/AI.Sentinel.ComplianceEval`: split field, judge option, three-configuration report.
- `SentinelReviewSetup` and the OpenAI-compatible chat client; host wiring in `src/AI.Sentinel.ClaudeCode.Cli/Program.cs`, `src/AI.Sentinel.Copilot.Cli/Program.cs`, `src/AI.Sentinel.Mcp/McpProxy.cs` and `McpPipelineFactory.cs`, and `src/AI.Sentinel.Cli/ScanCommand.cs` and `ForensicsPipelineFactory.cs`.
- `docs/superpowers/evaluations/2026-10-17-compliance-detectors.md`.
