---
sidebar_position: 3
title: Screening
---

# Screening text without a chat call

`ScreenAsync` runs one text through the same detectors, redaction and audit as a chat call, without a chat call. Use it for text that is not sent to a model right away: a submitted form, a support ticket, an incident report. You get the verdict and the masked text back, and only the masked text moves on to storage, triage or retrieval.

It is not a second scanner. It uses the options, the verdict rule, the alerts, the intervention and the audit entries of the middleware, so a screened text and a chat prompt cannot disagree.

## Calling it

Resolve `ISentinelScreener` from DI after `AddAISentinel`. It is a singleton, unkeyed for the default pipeline and keyed by name for a [named pipeline](/docs/configuration/named-pipelines). The pipeline is built on first use, so registering it has no side effects.

```csharp
using System.Diagnostics;

public sealed class TicketIntake(ISentinelScreener screener)
{
    public async Task<string?> MaskAsync(string text, CancellationToken ct)
    {
        var outcome = await screener.ScreenAsync(text, ct: ct);

        return outcome switch
        {
            ScreeningOutcome.Passed passed           => passed.RedactedText,
            ScreeningOutcome.Quarantined             => null, // keep it out of triage
            ScreeningOutcome.RateLimited limited     => throw new InvalidOperationException($"Try later: {limited.SessionKey}"),
            ScreeningOutcome.Failed failed           => throw new InvalidOperationException(failed.Message, failed.Inner),
            _ => throw new UnreachableException(),
        };
    }
}
```

With a pipeline in hand, `SentinelPipeline.ScreenAsync(text, options, ct)` has the same signature. A named pipeline is resolved with `[FromKeyedServices("name")] ISentinelScreener`.

## The four outcomes

A verdict is a value, never an exception.

| Case | Meaning |
|------|---------|
| `Passed` | The text may move on. `Action` is the most restrictive effective action of the detections: `PassThrough`, `Log` or `Alert`. |
| `Quarantined` | The scan quarantined the text. `RedactedText` is still masked. Whether you keep or drop it is up to you. |
| `RateLimited` | The rate limit refused the call. Nothing was masked or scanned. `SessionKey` is the key that ran out. |
| `Failed` | The pipeline itself failed: masking failed, or the scan or its audit threw. `Message` never holds the screened text. |

`Passed` and `Quarantined` carry the same fields:

- `RedactedText`: the input with every masked value replaced by its placeholder.
- `Detections`: every non-clean detection of the scan, empty for a clean text.
- `Redactions`: every masked occurrence, in input order.
- `Session`: the session the audit entries were written for.

`Failed.Inner` holds the underlying exception when the scan or its audit threw. A masking failure keeps none, because its message can carry the value.

## Redactions

Each `RedactionFinding` is one masked occurrence: `Detector`, `EntityType`, `Start`, `Length`, `Placeholder` and an optional `Severity`. `Start` and `Length` are offsets in the **input** text, not in `RedactedText`. The value itself is not kept. Only spans that were actually replaced are listed; where two detectors report overlapping spans, the one that did not mask is left out.

`Severity` is what the detector gave the span, or `null` when it gave none. `PiiLeakageDetector` sets it: a credit card number is `Critical`, an SSN, IBAN, BSN, NINO, passport number or German tax ID is `High`, and an email address, phone number or date of birth is `Medium`. A [custom redacting detector](/docs/custom-detectors/writing-a-detector#redacting-detectors) can set it too.

To list what was found per type, group by `EntityType`:

```csharp
if (outcome is ScreeningOutcome.Passed { Redactions: { Count: > 0 } redactions })
{
    foreach (var group in redactions.GroupBy(r => r.EntityType))
        Console.WriteLine($"{group.Key}: {group.Count()}");   // PHONE: 1, DATE_OF_BIRTH: 1
}
```

## Readable placeholders

By default the masked text holds the library tokens, such as `[PHONE_1_k3f9x2]`. To show something readable, pass a formatter. It is called once per finding, with `Placeholder` set to the library token, and it never sees the value.

```csharp
var options = new ScreeningOptions
{
    Placeholder = finding => finding.EntityType switch
    {
        "PHONE" => "[TELEFOON]",
        "EMAIL" => "[E-MAIL]",
        _       => $"[{finding.EntityType}]",
    },
};

var outcome = await screener.ScreenAsync("Bel Jan de Vries op 0612345678.", options, ct);
// Passed.RedactedText: "Bel Jan de Vries op [TELEFOON]."
```

The formatter runs after the scan and the audit. The scan always judges the library tokens, so the formatter cannot change the verdict. A value that occurs twice shares one token, and the formatter's output is used at every occurrence. In the outcome, `RedactionFinding.Placeholder` is the formatter's output. An exception the formatter throws reaches the caller as it is, and a formatter that returns `null` throws an `InvalidOperationException`.

## Sessions and the rate limit

`ScreeningOptions.Session` names the session the audit entries and the outcome belong to. It is also the rate-limit key, as it is on the chat path.

Without a session, the call gets a new one. A session minted for the call is never a rate-limit key, since every call would get its own bucket, so the call is limited on the shared `__global__` key. Pass a session when you want a per-user or per-ticket limit.

## Audit

The same entries as a chat call, and with the same rules:

- A **clean** text writes nothing.
- A **masked** text writes the informational `REDACTED` entry per redacting detector, with counts only, such as `Redacted 1 PHONE, 1 DATE_OF_BIRTH`. See [Audit and notifications](./redaction#audit-and-notifications).
- A **quarantined** text writes its detections and, when anything was masked, the `REDACTED` entries too: the masked text is returned either way.

No masked value reaches an audit entry, an exception message or a `ToString()`.

## Fails closed

If masking fails, the outcome is `Failed`. The text is never scanned or returned unmasked, because returning the input as "masked" would put the personal data exactly where the caller promised it would not go.

If the scan or its audit throws, for example because the audit store cannot write, the outcome is `Failed` too, with the exception in `Inner`. An exception a placeholder formatter throws is not caught: it reaches the caller as it is.

## Cancellation

Cancelling `ct` throws `OperationCanceledException`. It is never reported as `Failed`. A null `text` throws `ArgumentNullException`.
