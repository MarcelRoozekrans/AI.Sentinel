# Screening API: `ScreenAsync` (#492)

## Intent

An app sometimes has to screen text that is not sent to a model right away: a submitted form, a ticket, an incident
report. It must be checked for PII and prompt injection before it is stored or routed. In 3.6.2 there is no public
call for that, so an app combines a fake terminal `IChatClient`, a second `IDetectionPipeline.RunAsync` pass and its
own span handling, and still loses findings on the quarantine path.

The first user is an incident-triage demo, an offline Blazor app. Its screening step masks PII in a Dutch report and
quarantines manipulation attempts. Only the masked text moves on to triage and retrieval. Its go/no-go for library
releases is **Saturday 31 October 2026, 18:00**; this ships as a `feat:` in 3.7.0 before then. The demo does not
wait for it: without a release it keeps its tested two-pass adapter.

Success: the demo replaces its two passes with one `ScreenAsync` call, and the dashboard shows the same entries for a
screened text as for a chat call, blocked ones included, with no chat client in sight. As on the chat path, a clean
text writes no entry.

## Goals

1. One call returns the verdict, the masked text, every detection and every redaction, also when the text is
   quarantined.
2. Same detectors, options, verdict rule (`SentinelOptions.EffectiveAction`), intervention, alerts and audit entries
   as the middleware, so the two paths cannot disagree.
3. The outcome is a value. A threat verdict, a rate-limit refusal and a pipeline failure are distinct; cancellation
   surfaces as `OperationCanceledException`.
4. Apps can render readable placeholders such as `[TELEFOON]`.
5. Fix the defects the issue found in the existing middleware path, since they are the same root causes.

## Non-goals

- Restoring masked values. Screening returns the masked text; there is no response to restore into.
- Multi-message or JSON screening. One string in. The internal host path keeps handling JSON for MCP and hooks.
- A release or approval action for quarantined text.
- `AddAISentinel` registering twice, and the source-generated `GeneratedAuthorizationRegistration` from
  ZeroAlloc.Authorization shipping as a public type and causing CS0121 in apps that also use that package. Both are
  real, both are in other areas: each gets its own issue.

## Anti-goals

- A second scanning code path with its own verdict logic. `ScreenAsync` must reuse what the hooks and MCP proxy use.
- PII in the audit log. Redaction audit stays counts only; values never leave the call except in the caller's own
  returned offsets.
- Throwing for a verdict.

## Decided

### Public surface

On `SentinelPipeline`:

```csharp
public ValueTask<ScreeningOutcome> ScreenAsync(
    string text, ScreeningOptions? options = null, CancellationToken ct = default);
```

`ScreeningOptions` carries `SessionId? Session` (null mints one) and
`Func<RedactionFinding, string>? Placeholder` (null keeps the library's `[TYPE_n_tag]` tokens).

A DI entry point, so no chat client is needed: `AddAISentinel` registers `ISentinelScreener` with the same
`ScreenAsync` signature, unkeyed for the default pipeline and keyed by name for a named pipeline. It is backed by a
`SentinelPipeline` whose inner client is never called. Lifetime: singleton per pipeline name, so the
pipeline's rate-limit state persists across calls. The internal `UnusedChatClient` copies in the MCP and Claude
Code packages may move to one shared internal type.

`ScreeningOutcome` is a closed record hierarchy in the style of `SentinelError`:

- `Passed`: `Action` (PassThrough, Log or Alert: the most restrictive effective action of the findings),
  `RedactedText`, `Detections`, `Redactions`. Quarantine is the only action that produces `ThreatDetected`;
  `EffectiveAction` never returns Redact, so there is no other case.
- `Quarantined`: the same fields, with `Action` Quarantine. `RedactedText` is still masked.
- `RateLimited(string SessionKey)`: nothing was scanned.
- `Failed(string Message, Exception? Inner)`: the pipeline itself failed, including a failed redaction. Not used
  for cancellation.

Common to the scanned cases: `SessionId Session`.
`Detections` is every non-clean `DetectionResult` of the scan, with its effective action.
`Redactions` is a list of `RedactionFinding`.

`RedactionFinding(DetectorId Detector, string EntityType, int Start, int Length, string Placeholder)` plus
`Severity? Severity`. One item per masked occurrence, `Start`/`Length` relative to the **input** text,
`Placeholder` the string that replaced it in `RedactedText`. Only spans that were actually replaced are listed:
where spans overlap, the session's existing rule (`RedactionSpanCollector.Normalize`, then detector order) decides
which one masks, and the dropped one is not listed.

The formatter is called once per finding, with `Placeholder` set to the library token; it never sees the original
value. In the outcome, `Placeholder` is the formatter's output. A token shared by repeated identical values gets the
formatter's output for each occurrence. Grouping per detector and entity type is a LINQ
`GroupBy` away and the issue's "PHONE and DATE_OF_BIRTH appear separately" falls out of it.

### Severity on redactions is opt-in

`RedactionSpan` gets an optional `Severity? Severity { get; init; }`, null by default. Detectors that set it get it
reported on the `RedactionFinding`; the rest report null. The demo leaves it off for its own detectors. SEC-23 fills
it in from the severities it already uses in `AnalyzeAsync` (credit card Critical, SSN/IBAN/BSN/NINO/passport/tax id
High, email/phone/date of birth Medium). Additive change to a public `readonly record struct`.

### How it runs

`ScreenAsync` is built on the internal `RedactAndScanAsync` with one `HostContent.FromText(text)` item, the path the
Claude Code hooks and the MCP proxy already use:

1. Rate limit check, keyed on the caller's `Session` when one is given, otherwise on the shared `__global__` key,
   as the chat path does without a session. A session minted for the call is never a rate-limit key: that would
   give every call its own bucket.
2. Mask with a `RedactionSession`, with the library's tokens.
3. Scan the masked text with this call's tokens exempt; detection audit, metrics, alerts and intervention as today.
4. **Always** write the REDACTED audit entries and the Redact notification when anything was masked, also when
   quarantined: the masking happened and the masked text is returned to the caller.
5. Map the internal result to `ScreeningOutcome`. With a `Placeholder` formatter, swap each minted token in the
   masked text for the formatter's output in one final pass. The scan always sees the library's tokens, so the
   formatter cannot change the verdict.
6. When redaction fails, the outcome is `Failed`. Screening fails closed, like the chat path (`RedactionFailed`)
   and the hooks since #478: returning the unmasked input as "masked" text would put PII exactly where the caller
   promised it would not go. The host path's fallback to an unredacted scan stays for MCP and hooks; screening
   does not use it.

`RedactAndScanAsync` and `RedactionSession` need to expose the spans they replaced, relative to the input, with
detector id and severity. Today they only keep counts and tokens.

### Middleware fixes (same root causes)

- **All detections on quarantine.** `SentinelError.ThreatDetected` gains `IReadOnlyList<DetectionResult> Detections`
  as an init property, defaulting to `[Result]`. `ScanAsync` fills it from the full `PipelineResult` it currently
  discards. `ToException()` builds the `PipelineResult` from it, with the score of the full set.
- **Redaction audit on quarantine.** The chat path writes the REDACTED entries when the prompt scan quarantines,
  with the same rule as step 4.
- **SEC-23 reports every PII type.** When SEC-23 runs as a plain detector, not masking, its one `DetectionResult`
  names every type it found at the highest severity among them, for example "Phone number and date of birth
  detected", instead of only the first hit.
- **Cancellation is not wrapped.** An `OperationCanceledException` from the inner client while `ct` is cancelled
  propagates as is, instead of becoming `PipelineFailure` and then an `InvalidOperationException`.
- **Typed session id in `ChatOptions`.** `SessionIdKey` also accepts a `SessionId` value. The rate limiter reads
  `SessionIdKey` only; without it the call keeps the `__global__` key. `ConversationId` still groups the audit but is
  not a rate-limit key: with the OpenAI Responses API it is the previous response id, so each turn would get a fresh
  bucket and the limit would be off.

## Constraints

- .NET 10, existing analyzers (Meziantou, Roslynator, ErrorProne.NET, ZeroAlloc). XML docs on every public member.
- No public API tracking file exists; the changelog and README are the record.
- AOT and trimming as for the rest of the package.
- xUnit v3 and NSubstitute in `tests/AI.Sentinel.Tests`.
- Commit bodies without nested parentheses (release-please).
- Fits the 31 October deadline: one PR, reviewed, released.

## Left to the builder

- Internal shape of the span export from `RedactionSession`, and whether `HostRedactionResult` grows the spans or a
  new internal result type is used.
- File layout and names of the internal types; whether `ISentinelScreener`'s implementation is a thin class or the
  pipeline itself.
- Exact wording of SEC-23's combined reason.
- Test layout, as long as there are tests for: the demo's three reports (clean, PII, injection) and a mixed
  PII-plus-injection report that comes back quarantined with its PII masked and listed; audit entries on both
  paths; the formatter; rate limit; cancellation; fallback; the middleware fixes.
- README and docs updates for the new API.
