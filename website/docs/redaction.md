---
sidebar_position: 2
title: Redaction
---

# Redaction

Redaction is **allow, minus the sensitive parts**. When `PiiLeakageDetector` or `CredentialExposureDetector` finds personal data or a secret in a request, AI.Sentinel replaces each value with a numbered placeholder and lets the call through. The model sees `[EMAIL_1]`, the user still gets a useful answer, and the real value is put back before the reply reaches the caller.

Redact is **not a block**. Nothing throws, the call is not quarantined, and a redaction is not counted as a threat.

:::warning 3.0 changes the default
From 3.0, `PiiLeakageDetector` and `CredentialExposureDetector` redact by default. Before 3.0 they used the action of their severity (a Critical finding could quarantine the call). To restore that behaviour with one line:

```csharp
services.AddAISentinel(opts => opts.RedactByDefault = false);
```
:::

## Why

- **GDPR Art. 5(1)(c), data minimisation:** the model receives only the personal data it needs, and usually it needs none.
- **GDPR Art. 25, data protection by design:** the safe behaviour is the default.
- **EU AI Act Art. 10:** the README row moves from "detects" to "detects and keeps it away from the model". Art. 10 is mainly about the training, validation and test data of high-risk systems, so treat this as a building block, not as compliance on its own.

## What the model sees

```text
user:   Mail jan@acme.nl and ask him to pay NL91ABNA0417164300. Use api_key=sk-live-9f8e7d6c5b4a.
model:  Mail [EMAIL_1] and ask him to pay [IBAN_1]. Use api_key=[API_KEY_1].
```

- Placeholders have the form `[TYPE_n]`. They are numbered per type within one call, starting at 1.
- The same value always gets the same placeholder within a call.
- A credential span masks the value only and keeps the key name, so the model still sees the structure (`api_key=[API_KEY_1]`). A PEM private key is masked from its header to its end marker.
- Text that already looks like a placeholder, such as a user typing `[EMAIL_1]`, is never restored to a real value. Only placeholders created by this call are restored.

### Entity types

| Detector | Types |
|---|---|
| `PiiLeakageDetector` | `CREDIT_CARD`, `SSN`, `IBAN`, `BSN`, `NINO`, `PASSPORT`, `TAX_ID`, `EMAIL`, `PHONE`, `DATE_OF_BIRTH` |
| `CredentialExposureDetector` | `PASSWORD`, `API_KEY`, `SECRET_KEY`, `BEARER_TOKEN`, `AWS_SECRET`, `PRIVATE_KEY`, `GITHUB_TOKEN` |

`PiiLeakageDetector` now also matches a bare email address. Before 3.0 it only matched an address preceded by a capitalised "First Last" name.

## Everything sent to the model is redacted

Not only the latest prompt. AI.Sentinel redacts the text of every message in every role, earlier turns in the history, tool-call arguments, tool results (strings, JSON, `AIContent` and serialized objects), reasoning and text attachments. Without this, a value restored for one turn would go back to the model as history in the next.

## Restoring

The response scan runs on the reply as the model produced it, still with placeholders. Restoring happens afterwards, so restored values never trigger a response detection.

| Where | Restored |
|---|---|
| Reply text | Yes |
| Tool results in the returned history | Yes |
| Tool-call arguments for PII | Yes, before the tool runs |
| Tool-call arguments for secrets | **Never** |

Streaming works the same way. A placeholder split across chunks (`[EMA` + `IL_1]`) is handled.

To keep placeholders in the reply and in tool calls:

```csharp
services.AddAISentinel(opts => opts.RestoreRedactedValues = false);
```

### Secrets are not restored into tool calls

A prompt-injected model could try to exfiltrate a pasted key by calling a tool with a guessed placeholder. So `[API_KEY_1]` stays a placeholder in a tool call, and a tool that needs a secret must get it another way (configuration, a vault). Secrets are restored in the reply to the user.

### Tool calls

When the model calls `send_email(to: "[EMAIL_1]")`, the tool runs with the real address. This works in either builder order: `UseAISentinel`, `UseFunctionInvocation` and `UseToolCallAuthorization` can be added in any order. Tool-call authorization judges the real values. A tool's exception message is redacted before it can reach the model. `InnerException` keeps the original for your application, so logging the whole exception logs the original.

:::note Known limitation
With Sentinel placed inside `UseFunctionInvocation`, a secret placeholder left in a tool call can be renumbered on the next model round trip. A reply that quotes the old token then shows the placeholder to the user. Nothing leaks.
:::

## Configuring

Redact is a `SentinelAction`, set per detector:

```csharp
services.AddAISentinel(opts =>
{
    // Redact (the 3.0 default for these two detectors)
    opts.Configure<PiiLeakageDetector>(c => c.Action = SentinelAction.Redact);

    // Keep the 2.x behaviour for one detector
    opts.Configure<CredentialExposureDetector>(c => c.Action = SentinelAction.Quarantine);
});
```

`DetectorConfiguration.Action` overrides the severity mapping for that detector, so a Critical credential set to Redact is redacted, not quarantined. Validation throws on startup when:

- `OnCritical`, `OnHigh`, `OnMedium` or `OnLow` is set to `Redact`, because only some detectors can redact;
- `Action = Redact` is set on a detector that cannot redact (the semantic detectors cannot say where the data is).

### When detectors disagree

If any detection's effective action is `Quarantine`, the call is quarantined and nothing is sent. Otherwise every Redact detection is redacted, and the highest remaining action among the others (`PassThrough`, `Log`, `Alert`) applies as usual. Every other detector, such as prompt injection, judges the redacted text.

## Fallback

When redaction is not possible, the detection uses the action of its severity, as before, and its audit summary ends with `; not redacted`. That happens:

- in the **response scan**, because redaction only applies to what goes to the model;
- in the **hook CLIs and the MCP proxy** in 3.0, which cannot rewrite the request;
- when a detector **flags text without spans**.

## Fail closed

If redaction itself fails, the call fails with a pipeline failure. AI.Sentinel never sends unredacted text because redaction broke.

## The mapping is never stored

The placeholder to value mapping lives in memory for one `GetResponseAsync` or `GetStreamingResponseAsync` call. It is never logged, audited, forwarded or put in an exception, and it is not shared across calls. Numbering may differ between turns, because every request is redacted afresh from your history, which holds the real values.

## Audit and notifications

- **One informational audit entry per redacting detector per call**, with `PolicyCode = "REDACTED"`, `Severity = None` and a summary of counts only, such as `Redacted 1 EMAIL, 1 IBAN`.
- The entry is **in the hash chain and forwarded** like any other, so the compliance record is complete. A SIEM sees an informational entry with the `REDACTED` code.
- It **never moves** the severity tiles, the trend, the risk score, the threat metrics or an alert.
- OpenTelemetry logs it at Information.
- The [dashboard](/docs/getting-started/dashboard) shows a "redacted" badge and a "Redacted" filter chip.
- The caller is told through `InterventionAppliedNotification` with `Action = Redact` and the counts. `ThreatDetectedNotification` does not fire for a redaction alone.

## Policies and approvals see real values

Authorization policies and approval requests receive the real argument values, so an approver can judge the actual call. A user-written policy that puts argument values in its deny reason puts them in the audit. Keep values out of deny reasons.
