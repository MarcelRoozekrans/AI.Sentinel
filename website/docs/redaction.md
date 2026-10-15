---
sidebar_position: 2
title: Redaction
---

# Redaction

Redaction is **allow, minus the sensitive parts**. When `PiiLeakageDetector` or `CredentialExposureDetector` finds personal data or a secret in a request, AI.Sentinel replaces each value with a numbered placeholder and lets the call through. The model sees `[EMAIL_1_k3f9x2]`, the user still gets a useful answer, and the real value is put back before the reply reaches the caller.

Redact is **not a block**. Nothing throws, the call is not quarantined, and a redaction is not counted as a threat.

:::warning 3.0 changes the default and what is detected
From 3.0, `PiiLeakageDetector` and `CredentialExposureDetector` redact by default. Before 3.0 they used the action of their severity, so a Critical finding could quarantine the call. This line turns redaction off:

```csharp
services.AddAISentinel(opts => opts.RedactByDefault = false);
```

It makes PII and credential findings use the action of their severity again, as in 2.x, and nothing is redacted. It does **not** bring back 2.x detection. See [What changed regardless](#what-changed-regardless).
:::

### What changed regardless

These detection changes apply in 3.0 whatever `RedactByDefault` is set to, and on every surface: the prompt and response scans, the hook CLIs and the MCP proxy.

- `PiiLeakageDetector` matches **every email address**, at Medium severity, with the reason `Email address detected`. Before 3.0 it only matched an address preceded by a capitalised "First Last" name, with the reason `Email with name detected`.
- `CredentialExposureDetector` matches quoted keys and values, such as `"password": "hunter2"`, a private key of any PEM type (`EC`, `OPENSSH`, `ENCRYPTED` and so on, not only `RSA`), `AWS_SECRET_ACCESS_KEY:` as well as `AWS_SECRET_ACCESS_KEY=`, and a quoted YAML value on the line after its key. An unquoted value on the next line no longer matches.
- A credential reason names the type only, such as `Credential exposure: API_KEY`. Before 3.0 it quoted the first 20 characters of the match, part of the secret.

So if Medium findings block in your setup, a prompt or reply that contains any email address is now blocked: with `RedactByDefault = false` and `OnMedium = Quarantine` in an app, and with `SENTINEL_HOOK_ON_MEDIUM=Block` or `SENTINEL_MCP_ON_MEDIUM=Block` in the hook CLIs and the MCP proxy, which cannot redact in 3.0. With redaction on, the response scan still flags an email address the model writes itself.

There is no option that brings back the 2.x patterns. In an app you can stop the wider matches from blocking with a setting for the detector itself; each applies to every type of personal data it finds, not only email addresses:

```csharp
services.AddAISentinel(opts =>
{
    opts.RedactByDefault = false;
    // Log PII findings instead of applying the severity action
    opts.Configure<PiiLeakageDetector>(c => c.Action = SentinelAction.Log);
    // or: cap the severity of PII findings, or switch the detector off
    // opts.Configure<PiiLeakageDetector>(c => c.SeverityCap = Severity.Low);
    // opts.Configure<PiiLeakageDetector>(c => c.Enabled = false);
});
```

The hook CLIs and the MCP proxy have no per-detector setting: choose their `SENTINEL_HOOK_ON_MEDIUM` and `SENTINEL_MCP_ON_MEDIUM` with email addresses in mind.

## Why

- **GDPR Art. 5(1)(c), data minimisation:** the model receives only the personal data it needs, and usually it needs none.
- **GDPR Art. 25, data protection by design:** the safe behaviour is the default.
- **EU AI Act Art. 10:** the PII and credential detectors do not only detect personal data and secrets, they keep them away from the model. Art. 10 is mainly about the training, validation and test data of high-risk systems, so treat this as a building block, not as compliance on its own.

## What the model sees

```text
user:   Mail jan@acme.nl and ask him to pay NL91ABNA0417164300. Use api_key=sk-live-9f8e7d6c5b4a.
model:  Mail [EMAIL_1_k3f9x2] and ask him to pay [IBAN_1_k3f9x2]. Use api_key=[API_KEY_1_k3f9x2].
```

- Placeholders have the form `[TYPE_n_tag]`. They are numbered per type within one call, starting at 1.
- The tag, `k3f9x2` above, is drawn at random for every call: a lower-case letter and five lower-case letters or digits. Every placeholder of one call carries the same tag, and another call gets another one.
- The same value always gets the same placeholder within a call.
- A credential span masks the value only and keeps the key name, so the model still sees the structure (`api_key=[API_KEY_1_k3f9x2]`). A PEM private key is masked from its header to its end marker.
- Only placeholders this call created are restored. Anything else stays text: a user typing `[EMAIL_1]`, a placeholder from an earlier call, or one from an earlier model round trip.

### Entity types

| Detector | Types |
|---|---|
| `PiiLeakageDetector` | `CREDIT_CARD`, `SSN`, `IBAN`, `BSN`, `NINO`, `PASSPORT`, `TAX_ID`, `EMAIL`, `PHONE`, `DATE_OF_BIRTH` |
| `CredentialExposureDetector` | `PASSWORD`, `API_KEY`, `SECRET_KEY`, `BEARER_TOKEN`, `AWS_SECRET`, `PRIVATE_KEY`, `GITHUB_TOKEN` |

`PiiLeakageDetector` now also matches a bare email address. Before 3.0 it only matched an address preceded by a capitalised "First Last" name. See [What changed regardless](#what-changed-regardless).

## What is redacted

Not only the latest prompt. Without this, a value restored for one turn would go back to the model as history in the next. AI.Sentinel redacts:

- the text of every message in every role, including the system message and earlier turns in the history;
- `ChatOptions.Instructions`, which providers send as a system prompt. It is redacted in a copy of your options, which are never changed;
- tool-call arguments and tool results: strings, JSON, `AIContent` and serialized objects, including the results of tools the model calls during the call;
- the call inside a tool approval request or response, and the reason of an approval response;
- reasoning text;
- attachments of a text type: `text/*`, JSON, XML and any `+json` or `+xml` type, NDJSON, YAML, JavaScript and form data.

Not redacted: binary attachments such as images, audio and PDF files, content referenced by URI, hosted tool content such as `McpServerToolCallContent` or code interpreter calls, tool definitions, and the other `ChatOptions` fields such as `AdditionalProperties`. Keep personal data out of those.

## Restoring

The response scan runs on the reply as the model produced it, still with placeholders. Restoring happens afterwards, so restored values never trigger a response detection.

| Where | Restored |
|---|---|
| Reply text | Yes |
| Tool results in the returned history | Yes |
| Tool-call arguments for PII | Yes, before the tool runs |
| Tool-call arguments for secrets | **Never** |
| The call in a tool approval request | PII yes, secrets **never**, because the call runs once approved |

Streaming works the same way. A placeholder split across chunks (`[EMA` + `IL_1_k3f9x2]`) is handled.

To keep placeholders in the reply and in tool calls:

```csharp
services.AddAISentinel(opts => opts.RestoreRedactedValues = false);
```

### Secrets are not restored into tool calls

A prompt-injected model could try to exfiltrate a pasted key by calling a tool with its placeholder. So `[API_KEY_1_k3f9x2]` stays a placeholder in a tool call, and a tool that needs a secret must get it another way (configuration, a vault). Secrets are restored in the reply to the user.

### Tool calls

When the model calls `send_email(to: "[EMAIL_1_k3f9x2]")`, the tool runs with the real address. This works in either builder order: `UseAISentinel`, `UseFunctionInvocation` and `UseToolCallAuthorization` can be added in any order. Tool-call authorization judges the real values. A tool's exception message is redacted before it can reach the model. `InnerException` keeps the original for your application, so logging the whole exception logs the original.

:::note Known limitation
With Sentinel placed inside `UseFunctionInvocation`, every model round trip is a separate Sentinel call with its own tag. A secret placeholder left in a tool call keeps the tag of the round trip that made it, so the next round trip gives the secret another token and the old one stays text. A reply that quotes the old token shows the placeholder to the user. Nothing leaks, and the old token never resolves to another value.
:::

### Conversations kept by the provider

Some providers keep the conversation on their side and return a `ConversationId`, such as the OpenAI Responses API with storage on. The caller, or `UseFunctionInvocation`, then sends only the new messages, so the model still holds placeholders from earlier calls in its own history. Those carry another tag: they are never restored to a value of the current call, even when the current call numbers another value with the same type and number. When the model repeats one, the user or the tool sees the placeholder, never another person's value.

## Configuring

Redact is a `SentinelAction`, set per detector:

```csharp
services.AddAISentinel(opts =>
{
    // PII and credentials already redact by default in 3.0.
    // Quarantine a pasted secret instead of redacting it
    opts.Configure<CredentialExposureDetector>(c => c.Action = SentinelAction.Quarantine);

    // Log PII findings instead of redacting them
    opts.Configure<PiiLeakageDetector>(c => c.Action = SentinelAction.Log);
});
```

`DetectorConfiguration.Action` overrides the severity mapping for that detector, so a Critical credential set to Redact is redacted, not quarantined. `AddAISentinel` throws an `ArgumentException` when:

- `OnCritical`, `OnHigh`, `OnMedium` or `OnLow` is set to `Redact`, because only some detectors can redact;
- `Action = Redact` is set on an enabled detector that cannot redact. The semantic detectors cannot say where the data is.

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

The placeholder to value mapping lives in memory for one `GetResponseAsync` or `GetStreamingResponseAsync` call. It is never logged, audited, forwarded or put in an exception, and it is not shared across calls. Every request is redacted afresh from your history, which holds the real values, with a new tag, so a placeholder from an earlier turn is text in a later one.

## Audit and notifications

- **One informational audit entry per redacting detector per call**, with `PolicyCode = "REDACTED"`, `Severity = None` and a summary of counts only, such as `Redacted 1 EMAIL, 1 IBAN`.
- The entry is **in the hash chain and forwarded** like any other, so the compliance record is complete. A SIEM sees an informational entry with the `REDACTED` code.
- It **never moves** the severity tiles, the trend, the risk score, the threat metrics or an alert.
- OpenTelemetry logs it at Information.
- The [dashboard](/docs/getting-started/dashboard) shows a "redacted" badge and a "Redacted" filter chip.
- The caller is told through `InterventionAppliedNotification` with `Action = Redact` and the counts. `ThreatDetectedNotification` does not fire for a redaction alone.

## Policies and approvals see real values

Authorization policies and approval requests receive the real argument values, so an approver can judge the actual call. A user-written policy that puts argument values in its deny reason puts them in the audit. Keep values out of deny reasons.
