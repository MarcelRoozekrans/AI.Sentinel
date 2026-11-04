# Pipeline failure signal (#550)

## Intent

A caller that uses the detection pipeline as a gate, such as a capture guard that decides whether text may be
persisted, cannot tell a clean scan from one where part of the check did not run. `SafeAnalyzeAsync` turns a
throwing detector into `DetectionResult.Clean`, and nothing on `PipelineResult` says so. When the embedding endpoint
is down, the semantic detectors fall back to their rule layer and the result looks clean, so the gate opens.
`OnDetectorFailure` does not help such a caller: it is one host-wide callback that cannot be correlated with a scan,
and its message carries `ex.Message`.

The fix gives every scan its own failure signal, so a gate can treat an incomplete scan as unavailable.

## Goals

- `PipelineResult` reports which detectors did not run as configured, and why.
- `ScreeningOutcome.Passed` and `ScreeningOutcome.Quarantined` report the same, so a gate outside the library reads it
  from `ScreenAsync`.
- A scan is **complete** when every configured check ran as configured.

## Non-goals

- No behaviour change: chat, the hooks, the MCP proxy and `ScreenAsync` still treat a clean, incomplete scan as clean.
  Whether a hook should fail closed on an incomplete scan is a separate decision.
- No global fail-closed option on `SentinelOptions`. It would apply to every consumer of the pipeline.
- No change to `OnDetectorFailure`, the log messages or the audit entries.

## Anti-goals

- The signal must not carry exception messages or any part of the scanned text.
- A clean, complete scan must not allocate more than today.

## What counts as a failure

One entry per affected detector, with a kind:

| Kind | When | Today's result |
|---|---|---|
| `Threw` | The detector threw, other than the caller's own cancellation and a regex timeout | `Clean` |
| `RegexTimeout` | A `RegexMatchTimeoutException` | Critical, unchanged |
| `TextsNotEmbedded` | A semantic detector needed a text that could not be embedded, or its text selection threw | Scored on the texts that did embed, or rule layer only |
| `ExamplesNotEmbedded` | A semantic detector's example phrases could not be embedded | Rule layer only |
| `ReviewFailed` | The reviewer failed or timed out on one of the detector's results | Keeps its capped severity |

A review skipped because `MaxReviewsPerScan` ran out is not a failure: that is the configured limit. A detector
that matched in its rule layer after an embedding failure is still listed: the semantic layer did not run, even
though the finding stands.

A detector gets one entry. If it hits more than one kind in a scan, the earliest stage wins (embedding, then
analysis, then review), because that is the one that limited what ran.

## Approaches

- **A. Per-scan collector, init property (picked).** `RunAsync` keeps an array of failure kinds indexed like
  `_detectors`, the same pattern as `outcomes`. Each catch site writes into it. `BuildResult` turns it into
  `Failures`. Binary compatible, `feat:` in 5.x.
- **B. A failed `DetectionResult` in `Detections`.** No collector, but every consumer of `Detections` and `IsClean`
  sees a new kind of entry: scoring, intervention, the CLI formatters, the audit. It mixes what was found with what
  could not run.
- **C. A per-scan callback on `SentinelContext`.** Fixes correlation, but leaves each gate to wire up and collect.

Marcel picked A on 2026-11-04, and the entries with a reason over a bare id list.

## Decided shape

```csharp
public enum DetectorFailureKind { Threw, RegexTimeout, TextsNotEmbedded, ExamplesNotEmbedded, ReviewFailed }

public readonly record struct DetectorFailure(DetectorId Detector, DetectorFailureKind Kind);

public sealed record PipelineResult(ThreatRiskScore Score, IReadOnlyList<DetectionResult> Detections)
{
    public IReadOnlyList<DetectorFailure> Failures { get; init; } = [];
    public bool Complete => Failures.Count == 0;
}
```

`Failures` is an `init` property rather than a positional parameter, so the public constructor and `Deconstruct`
stay as they are. `ScreeningOutcome.Passed` and `ScreeningOutcome.Quarantined` get the same two members.

## Left to the builder

- The exact names, if a clash or an analyzer argues for others; the shape stays as above.
- How `TextsNotEmbedded` maps a failed text to the detectors that needed it, from `EmbeddedScan.Texts`.
- Where the collector array lives (a field on a per-scan state object or a parameter, like `outcomes`).
- Tests: one per kind through `RunAsync`, the precedence rule, a clean scan reports `Complete`, the budget-skipped
  review is not a failure, and `ScreenAsync` carries the failures. The docs page on detector failures gets a section
  on reading `Failures` from a gate.
