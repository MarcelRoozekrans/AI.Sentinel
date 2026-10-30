---
sidebar_position: 4
title: Migrating to 4.0
---

# Migrating to 4.0

4.0 adds a second-stage review to every pipeline: an embedding hit is treated as a candidate until a reviewer confirms it. That changes default severities, adds an abstract member for detector authors and changes what `EscalationClient` does. This page lists each change and what to do about it. The [detectors overview](../detectors/overview#second-stage-review) describes the feature itself.

## Semantic detections are capped at Medium

A semantic detector's result from embedding similarity is now reported at most at `Medium` unless a reviewer confirms a higher severity. The cap applies to the final severity, not the bucket: `SEC-01` maps its Medium bucket to High and its High bucket to Critical, and without a verdict both show as `Medium`.

- A fast-path regex match, such as `SEC-01`'s rule layer, is never capped and never reviewed.
- The public `SemanticDetectorBase.AnalyzeAsync(ctx, ct)` is unchanged and uncapped. The cap is pipeline behaviour, so a test that calls a detector directly still sees its bucket severity.
- With an embedding generator, no reviewer and at least one capped semantic detector whose severity the cap can lower, AI.Sentinel logs a warning at startup. `DescribeUnreviewedSemanticDetection()` returns the same text for hosts without a logger.

**What breaks:** a policy that blocks on `High` or `Critical` no longer blocks on an embedding hit alone. Set a reviewer, below, to get confirmed High and Critical detections back.

**To opt out** for one detector in one pipeline, which restores the 3.x severity:

```csharp
services.AddAISentinel(opts =>
{
    opts.Configure<PromptInjectionDetector>(c => c.CapSemanticSeverity = false);
});
```

`null` and `true` cap. An opted-out detector is still reviewed when a reviewer is set, and a verdict can lower or clear its finding.

### A floor raises the cap

A `SeverityFloor` above `Medium` raises the cap level to the floor; it does not remove the cap. The shown severity is the lower of the proposed severity and the higher of `Medium` and the floor. A Critical bucket with a High floor shows `High` until a verdict confirms `Critical`. A `SeverityCap` below `Medium` keeps working as before and holds every result below the semantic cap.

## `ReviewCriterion` is a new abstract member

Every detector built on `SemanticDetectorBase` must now override `ReviewCriterion`, and every `ILlmEscalatingDetector` must implement it:

```csharp
protected override string ReviewCriterion =>
    "Text that tells the assistant to reveal or ignore its instructions. A user asking how prompt injection works is not a match.";
```

State in one or two plain sentences the intent that counts as a hit, and name the closest legitimate look-alike that does not. Leave out braces: that keeps the prompt and its JSON answer format unambiguous. The reviewer reads it to decide whether a text matches.

**What breaks:** a third-party detector that derives from `SemanticDetectorBase` or implements `ILlmEscalatingDetector` no longer compiles until it adds the member.

## `EscalationClient` is now shorthand for a reviewer

`opts.EscalationClient = client` now means `opts.Reviewer = new LlmJudgeReviewer(client)`. Setting both is rejected at `AddAISentinel`. A named pipeline uses its own reviewer and does not inherit the default pipeline's. What the client is asked, and when, changes:

- **It sees more.** In 3.x it judged only the Medium-or-higher findings of the five rule-based `ILlmEscalatingDetector` detectors: `SEC-02`, `SEC-08`, `SEC-19`, `SEC-23` and `SEC-32`. Now it also judges every semantic detector's embedding hits, and near misses: texts that reach no bucket but score at or above the detector's `ReviewThreshold`, by default its Low threshold.
- **A verdict can create a finding.** A verdict on a near miss can set any severity up to the detector's highest bucket severity, raised to a configured `SeverityFloor` and limited by a configured `SeverityCap`, so the reviewer can report a finding the embeddings alone missed. A verdict on any candidate may confirm, raise, lower or clear it, up to that maximum; for a rule-based detector the maximum is `Critical`.
- **The prompt changed.** It now carries the detector's `ReviewCriterion`, the proposed severity and the highest severity a verdict may set, and asks whether the text matches the criterion. The text is still the last 64 KiB, fenced by a per-call random boundary, and the answer is still JSON.
- **Reviews are bounded.** At most `opts.MaxReviewsPerScan` reviews start per scan, default 4, highest proposed severity first; 0 turns the review off and a negative value is rejected. Each one may take `opts.ReviewTimeout`, default 5 seconds. A candidate over the budget, or whose review fails or times out, keeps its capped result. In 3.x every finding was escalated, one after the other, with no timeout of its own.
- **Reviews run concurrently,** so a scan waits for the slowest of its reviews, not for their sum.
- **Failures are louder.** A review that fails or times out is logged once per scan as a warning, where 3.x logged each failure at Debug. An unreadable answer now counts as no verdict, without a log line, and keeps the result.
- **Reasons changed.** A reviewed finding keeps the detector's reason and adds the outcome and the reviewer's reason: `Semantic match — high-severity threat pattern — Reviewed: confirmed — <reason>`. 3.x wrote `LLM escalated to High` or `LLM lowered to Low`, and kept the detector's reason on a confirmation. A capped finding reads `Semantic match — capped at Medium pending review`. Update dashboards, alert rules or tests that match on reason text.
- **Metrics.** Every candidate is counted on `sentinel.reviews`, tagged `outcome` and `detector`.

**What to do:** if you set `EscalationClient` for the rule-based detectors only, check the extra cost: up to four calls per scan instead of one per rule-based finding. Lower `MaxReviewsPerScan` to trade review coverage for cost, and pick a fast model, because the review is now on the hot path of semantic findings too.

## The CLI tools read `SENTINEL_REVIEW_*`

The Claude Code and Copilot hooks, the MCP proxy and `sentinel scan` build their own pipelines. Without a reviewer the cap leaves them able only to warn on a semantic detection, so they now read a reviewer from the environment, the way they read `SENTINEL_EMBEDDING_*`:

| Variable | Default | Purpose |
|---|---|---|
| `SENTINEL_REVIEW_ENDPOINT` | — | Full chat completions URL of the reviewer, any OpenAI-compatible host. Required to enable review |
| `SENTINEL_REVIEW_MODEL` | — | Model identifier. Required with the endpoint |
| `SENTINEL_REVIEW_API_KEY` | — | Bearer token. Omit for local servers that need none |
| `SENTINEL_REVIEW_MAX_PER_SCAN` | `4` | Reviews per scan. `0` turns the review off |
| `SENTINEL_REVIEW_TIMEOUT_MS` | `3000` in the hooks, `5000` otherwise | Per-review timeout in milliseconds |

The hooks default to 3 seconds because each hook call is a process on the agent's critical path. A malformed setting is reported on stderr by name, not ignored.

**What breaks:** a hook or proxy configured to block on `High` that relied on semantic detections now warns on them, until `SENTINEL_REVIEW_ENDPOINT` and `SENTINEL_REVIEW_MODEL` are set.

**Before you set it:** the review endpoint receives each flagged text, which can contain the secret or personal data a credential or PII detector flagged, just as the embedding endpoint does. Choose a provider you would trust with that data, or a local one. The reviewer's reason reaches the model through the block or warning text; it is sanitised to one line and capped at 200 characters.
