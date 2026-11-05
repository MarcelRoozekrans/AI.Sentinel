# Hook review timeout Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The hook CLIs wait 5 s for a judge review, read from the one `ReviewLimits.Default`, so a slow review of a real positive is no longer abandoned.

**Architecture:** Delete the two copies of `DefaultReviewLimits` in the hook CLIs and read `ReviewLimits.Default`. The eval tool's two deployment tiers collapse into the one library tier. README documents the value.

**Tech Stack:** C#, .NET, xUnit.

**Spec:** `docs/superpowers/specs/2026-11-05-hook-review-timeout-design.md`

## Global Constraints

- Review timeout default: 5 s, from `ReviewLimits.Default` (internal, `AI.Sentinel.Detection`). `MaxPerScan` stays 4.
- No new project, no new public API. `SENTINEL_REVIEW_TIMEOUT_MS` keeps overriding the default.
- The recorded measurements in `docs/superpowers/evaluations/2026-10-17-compliance-detectors.md` stay unchanged.
- Commit type `fix:` for the CLI change. No nested parentheses in commit bodies, no Claude signatures or session links.
- Test with filters, never the whole DLL without `-noclass "*DetectorRegistrationTrimTests"`. Run `dotnet format whitespace --verify-no-changes` before each push.

## Review Focus

- `SENTINEL_REVIEW_TIMEOUT_MS` set to a value other than the default still wins in both CLIs, and `SENTINEL_REVIEW_MAX_PER_SCAN` too.
- A reviewer that answers after 3 s but before 5 s still produces its verdict in a hook pipeline built by `BuildProvider`.
- The eval note still names each review over the remaining default and reads correctly when none is over.

---

### Task 1: Hook CLIs read `ReviewLimits.Default`

**Files:**
- Modify: `src/AI.Sentinel.ClaudeCode.Cli/Program.cs:326-333,426`
- Modify: `src/AI.Sentinel.Copilot.Cli/Program.cs:324-331,424`
- Test: `tests/AI.Sentinel.Tests/ClaudeCode/HookCliTests.cs:384-404`
- Test: `tests/AI.Sentinel.Tests/Copilot/CopilotHookCliTests.cs:480-487`

**Interfaces:**
- Consumes: `ReviewLimits.Default` (`ReviewLimits`, 4 and 5 s).
- Produces: `Program.ReviewLimitsFor(SentinelReviewSetup? review)` in each CLI, unchanged signature, now defaulting to `ReviewLimits.Default`. `Program.DefaultReviewLimits` no longer exists.

- [ ] **Step 1: Update the tests to expect the library default.** In `HookCliTests`, rename `ClaudeCodeHook_ReviewTimeoutDefaultsTo3s` to `ClaudeCodeHook_ReviewTimeoutDefaultsToTheLibraryDefault`. Replace both `TimeSpan.FromSeconds(3)` assertions with `ReviewLimits.Default.Timeout` and the `4` with `ReviewLimits.Default.MaxPerScan`. Add `Assert.Equal(ReviewLimits.Default, Program.ReviewLimitsFor(null))`. In `CopilotHookCliTests` rename `CopilotHook_ReviewTimeoutDefaultsTo3s` to `CopilotHook_ReviewTimeoutDefaultsToTheLibraryDefault`, use the same expected values, and add the same `ReviewLimitsFor(null)` assertion plus an override check: `SentinelReviewSetup.TryCreateFromEnvironment` with `SENTINEL_REVIEW_TIMEOUT_MS` = `1500` gives `ReviewLimitsFor(setup).Timeout` of 1500 ms, as the ClaudeCode test already does.
- [ ] **Step 2: Run them and see them fail.** Run: `dotnet test tests/AI.Sentinel.Tests --filter "FullyQualifiedName~ReviewTimeoutDefaultsToTheLibraryDefault"`. Expected: both FAIL, expected 5 s but got 3 s.
- [ ] **Step 3: Remove `DefaultReviewLimits` from both CLIs.** Delete the property and its summary. `ReviewLimitsFor` becomes `new(review?.MaxReviewsPerScan ?? ReviewLimits.Default.MaxPerScan, review?.ReviewTimeout ?? ReviewLimits.Default.Timeout)`, and `var limits = reviewLimits ?? ReviewLimits.Default;` in `BuildProvider`. Reword the `ReviewLimitsFor` summary to say the unset values come from `ReviewLimits.Default`, with no mention of 3 s.
- [ ] **Step 4: Run the filter again, then the CLI test classes.** Run: `dotnet test tests/AI.Sentinel.Tests --filter "FullyQualifiedName~HookCliTests|FullyQualifiedName~CopilotHookCliTests"`. Expected: PASS.
- [ ] **Step 5: Commit.** `git add src tests && git commit -m "fix(hooks): wait the library default of 5 s for a judge review"` with a body saying the hook CLIs abandoned slow reviews of real positives at 3 s and now share `ReviewLimits.Default`. Refs #537.

### Task 2: Eval tool and README follow the single default

**Files:**
- Modify: `tools/AI.Sentinel.ComplianceEval/ReviewEvaluation.cs:25-41,205-225,290`
- Modify: `tools/AI.Sentinel.ComplianceEval/Program.cs:24,195`
- Modify: `README.md:956` and the paragraph below the review table

**Interfaces:**
- Consumes: `ReviewLimits.Default.Timeout`.
- Produces: `DeploymentTimeouts` holds one entry, `("the library default", ReviewLimits.Default.Timeout)`. `NoteReviewDurations` names reviews over that entry.

- [ ] **Step 1: Collapse `DeploymentTimeouts` to the one library entry.** Remove the hook entry and reword the summary, which names `DefaultReviewLimits` in the CLIs. `NoteReviewDurations` keeps its shape: the count line, then one bullet per review over the default. Its comment about "the shortest default" becomes "name each review over the default". Update the `TimedReviewer` summary if it mentions several defaults.
- [ ] **Step 2: Reword the two report strings in `Program.cs`** (the comment at line 24 and the configuration text at line 195) so they speak of reviews over the library's and the hook CLIs' shared 5 s default, and each review over 5 s is named.
- [ ] **Step 3: Update the README.** The `SENTINEL_REVIEW_TIMEOUT_MS` row default becomes `5000`. Add one sentence below the table: a hook waits at most that long for the judge, a review that takes longer keeps the capped Medium result, and lowering the timeout trades recall on confirmed findings for latency.
- [ ] **Step 4: Build and check.** Run: `dotnet build tools/AI.Sentinel.ComplianceEval` and `grep -rn "DefaultReviewLimits\|hook CLIs' default\|3000 for the hooks" src tools README.md`. Expected: build succeeds, grep finds nothing.
- [ ] **Step 5: Format, full filtered run, commit.** Run `dotnet format whitespace --verify-no-changes`, then the test DLL with `-noclass "*DetectorRegistrationTrimTests"` on both TFMs. Expected: green apart from the three DashboardCommandTests that fail on main too. Commit: `docs(eval): one review timeout default for hooks and library`, body ending with Refs #537.
