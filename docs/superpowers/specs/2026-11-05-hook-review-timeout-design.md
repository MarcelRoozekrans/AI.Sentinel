# Hook review timeout: one default, 5 s (#537)

## Intent

A hook CLI abandons a second-stage review after 3 s and keeps the capped Medium result. Real judge latency sits at that line. In the #433 held-out evaluation, 4 reviews of prohibited requests took 3.1 to 3.8 s and none took longer than 5 s, so under the hook default CMP-01 recall drops from 1 of 2 to 0 of 2 and CMP-02 and CMP-03 each lose a High. A real positive passes as a warning. That is a fail-open gap.

## Goals

- A review that the library default would finish also finishes in a hook.
- One value for the review timeout, with no mirrored copies that can drift.

## Non-goals

- No change to `MaxPerScan`, which stays 4 everywhere.
- No change to the `SENTINEL_REVIEW_TIMEOUT_MS` mechanism; it remains the knob to go back to 3000.
- No new project and no new public API. `ReviewLimits` stays internal.
- The recorded measurements in `docs/superpowers/evaluations/2026-10-17-compliance-detectors.md` are history and stay as they are.

## Approaches

1. **Hook default equals `ReviewLimits.Default` (5 s); delete the copies.** Chosen. Reviews run in parallel, so a hook waits at most one timeout, and 5 s fits the 10 s per-hook allowance in the Copilot config. Hooks, the MCP proxy and `AddAISentinel` hosts share one default.
2. Keep 3 s and document that a slow judge loses verdicts. Rejected: it keeps the gap open and tells the user to fix it themselves.
3. 8 s, or a named hook constant beside `Default`. Rejected: 8 s eats most of the 10 s hook allowance, and a hook-only constant would be a second value that equals the first.

## Design

- `AI.Sentinel.ClaudeCode.Cli/Program.cs` and `AI.Sentinel.Copilot.Cli/Program.cs`: remove `DefaultReviewLimits`. `ReviewLimitsFor` and the pipeline build read `ReviewLimits.Default`. Update the comment that says a hook gets 3 s.
- `tools/AI.Sentinel.ComplianceEval/ReviewEvaluation.cs`: `DeploymentTimeouts` loses the hook entry, because the two tiers are now the same value. The review-duration note counts reviews over the one remaining default, `ReviewLimits.Default.Timeout`. Reword its comments and the note text, which names the hook CLIs' default.
- `README.md`: the `SENTINEL_REVIEW_TIMEOUT_MS` row says `5000`, and one sentence says a hook waits at most that long for a judge and that lowering it trades recall on confirmed findings for latency.
- Tests: the three assertions of 3 s in `HookCliTests` and `CopilotHookCliTests` expect `ReviewLimits.Default.Timeout`. A test pins that `ReviewLimitsFor(null)` equals `ReviewLimits.Default` in both CLIs, and that `SENTINEL_REVIEW_TIMEOUT_MS` still overrides it. Eval tests that count the hook tier are updated to the single tier.

## Release

`fix:`, so a patch release. Commit bodies avoid nested parentheses.

## Left to the builder

The exact wording of the README sentence and the eval note.
