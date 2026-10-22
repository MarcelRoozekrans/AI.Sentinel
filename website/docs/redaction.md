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

So if Medium findings block in your setup, a prompt or reply that contains any email address is now blocked: with `RedactByDefault = false` and `OnMedium = Quarantine` in an app, and with `SENTINEL_HOOK_ON_MEDIUM=Block` or `SENTINEL_MCP_ON_MEDIUM=Block` wherever the hook CLIs and the MCP proxy cannot redact, such as a Claude Code prompt or the arguments of a tool call. See [Per surface](#per-surface). With redaction on, the response scan still flags an email address the model writes itself.

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
- hosted tool calls and their results: the arguments of an MCP server tool call (`McpServerToolCallContent`), the code of a code interpreter call, the queries of a web search call, and the outputs of their results;
- the tool call inside a tool approval request or response, including a hosted call, and the reason of an approval response;
- reasoning text;
- attachments of a text type: `text/*`, JSON, XML and any `+json` or `+xml` type, NDJSON, YAML, JavaScript and form data.

Not redacted: binary attachments such as images, audio and PDF files, content referenced by URI, image generation calls, which carry no text, tool definitions, and the other `ChatOptions` fields such as `AdditionalProperties`. Keep personal data out of those.

## Per surface

The in-process chat client sees the whole conversation and rewrites it. The hook CLIs and the MCP proxy can only rewrite what their host lets them rewrite, so each surface redacts a different part. Redaction is on by default in the hook CLIs and the MCP proxy. `SENTINEL_HOOK_REDACT=off` turns it off in the hook CLIs, and `SENTINEL_MCP_REDACT=off` turns it off in the MCP proxy. Unset, the proxy follows `SENTINEL_HOOK_REDACT`. A host that calls `HookAdapter` or `CopilotHookAdapter` from the libraries opts in with `RedactToolResults = true`; see [Library callers](#library-callers).

| Surface | What is redacted | Restored | Falls back |
|---|---|---|---|
| In-process client | Everything listed under [What is redacted](#what-is-redacted) | The reply, tool results, and PII in tool-call arguments; secrets never in tool calls | The response scan, and a detector that flags text without spans |
| MCP proxy | Tool results, prompts from `prompts/get`, and text resources from `resources/read` | PII placeholders in the arguments of a later `tools/call`, until `SENTINEL_MCP_REDACT_TTL_MIN` minutes after their last use, 30 by default; secrets never | Tool-call arguments, blob and non-allowlisted resources, content past the byte budget, and personal data inside a JSON key. A rate-limited scan or a pipeline error forwards the content unredacted |
| Claude Code `PostToolUse` | The tool output, returned as `updatedToolOutput` | No: the model keeps the placeholders | Personal data inside a JSON key |
| Claude Code `PreToolUse` | Nothing. The [placeholder guard](#placeholder-guard) denies writes and shell commands that carry a placeholder | No | The tool arguments |
| Claude Code `UserPromptSubmit` | Nothing | No | The prompt |
| Copilot `postToolUse` | The tool result's `textResultForLlm`, returned as `modifiedResult` | No | A tool result without a string `textResultForLlm` |
| Copilot `userPromptTransformed` | The transformed prompt, returned as `modifiedTransformedPrompt`. **Experimental**: not yet verified with the Copilot CLI | No | Nothing on the prompt itself |
| Copilot `preToolUse` | Nothing. The [placeholder guard](#placeholder-guard) applies | No | The tool arguments |
| Copilot `userPromptSubmitted` | Nothing | No | The prompt |

"Falls back" means the detection uses the action of its severity, as described under [Fallback](#fallback). On every surface except the in-process client, a failure of the redaction itself also falls back; see [Fail closed](#fail-closed).

When the hook CLIs and the MCP proxy redact JSON, such as a tool's output or `structuredContent`, they redact string values only, and keep every key, number and the nesting as they are.

- **A value recognised by its key** is redacted. The detectors judge a JSON value the way the scan renders it, together with its key: `"password": "hunter2"`. The value `hunter2` on its own matches nothing, but the pair does, so the value becomes `{"password":"[PASSWORD_1_k3f9x2]"}` and the key stays. Personal data named by its key, such as `{"BSN":"123456789"}`, is redacted the same way. When a span covers part of the key, only the part in the value is redacted, so `{"Authorization":"Bearer abc"}` becomes `{"Authorization":"Bearer [BEARER_TOKEN_1_k3f9x2]"}`. The in-process client does the same for tool-call arguments, tool results and other JSON it sends to the model. An item of an array and a bare string have no key and are judged on their own.
- **A value that holds a line break** is redacted as a whole, not up to the break.
- **A JSON literal** under a secret key, a bare `null`, `true` or `false` as in `{"password": null}`, names no secret and is not flagged.

Three cases fall back:

- **Personal data inside a JSON key** is scanned but not redacted, because renaming a key would break the shape of the JSON.
- **A value that is not a string** under a key that names a secret or personal data, such as the number in `{"password": 12345678}`, is flagged but not redacted, because a placeholder in its place would change its type.
- **A match that spans two members** in the scan text, such as one that runs from the value of one member into the next, is flagged but not redacted, because each value is redacted together with its own key only.

### MCP proxy

- **What is scanned.** With redaction on, the proxy redacts the text blocks of a tool result, embedded text resources whose MIME type is in `SENTINEL_MCP_SCAN_MIMES`, and the tool result's `structuredContent`. 3.0 did not scan embedded resources or `structuredContent` at all, so these can produce findings that 3.0 did not. A value that appears in both `structuredContent` and a text block is counted once per occurrence in the `REDACTED` summary.
- **The byte budget.** `SENTINEL_MCP_MAX_SCAN_BYTES` limits each block and is also the total budget for one scan of a tool result or prompt. The first item that does not fit in what is left is scanned truncated and is not redacted. The items after it pass unredacted and unscanned, as 3.0's truncation passed them unscanned. Resource items are budgeted one by one, and an oversize item is skipped, as in 3.0.
- **Restoring into tool calls.** When the agent calls a tool with a PII placeholder the proxy minted earlier in the same run, the tool gets the real value. A placeholder stays restorable until `SENTINEL_MCP_REDACT_TTL_MIN` minutes after its last use, 30 by default. The proxy holds up to 10,000 placeholders and evicts the least recently used. An expired or evicted placeholder reaches the tool as literal text. Secrets are never restored: the tool gets the placeholder.
- **Restored values are not scanned.** The request scan judges the arguments as the agent sent them, with placeholders. A restored email address sent to an outbound tool is therefore not flagged by the PII detector on the way out. An [authorization policy](./authorization/overview) sees the restored arguments and is the control for outbound tools.
- **Approvals store real values.** With `RequireApproval`, the approval store, SQLite included, keeps the restored real arguments, so an approver judges the actual call.
- **Only `tools/call` is restored.** A placeholder in the arguments of `prompts/get` or in a resource URI stays literal text.
- **Fallbacks.** When a scan is rate limited, or the pipeline throws, the content is forwarded unredacted, as 3.0 forwarded it unscanned. The rate-limited case is logged with `reason=rate_limited`.

### Hook CLIs

- **Claude Code** gets the redacted tool output as `updatedToolOutput`, with an `additionalContext` note that names the redacted types and tells the model not to write placeholders to files or commands. See [Claude Code → What each action does](./integrations/claude-code#what-each-action-does).
- **Copilot** gets the redacted text as `modifiedResult`. With redaction on, a secret or personal data in a Copilot tool result is now redacted and allowed, where it used to be blocked. With `SENTINEL_HOOK_REDACT=off` it is still blocked, as before.
- **Prompts are not redacted on Claude Code or on Copilot's `userPromptSubmitted`,** because neither lets a command hook rewrite the prompt. Copilot's `userPromptTransformed` can, and is experimental. See [Copilot → Prompt enforcement](./integrations/copilot#prompt-enforcement).
- **Withheld output.** When a `PostToolUse` scan blocks, on both hosts and also with redaction off, the output is withheld rather than delivered. For Claude Code, the withheld output keeps the shape of the tool's `tool_response`: identifier-like `type` values and empty strings are kept, and every other string becomes `withheld by AI.Sentinel: <reason>`. Claude Code rejects an output whose `type` changed and then shows the original, which is why `type` is kept. Copilot gets a `modifiedResult` with the withheld text. Copilot requires `resultType: "success"` on a `modifiedResult`, so a result whose original `resultType` was something else, such as `failure`, keeps that status as a prefix of the text: `[failure] withheld by AI.Sentinel: <reason>`. A redacted result is prefixed the same way.
- **No restore.** A hook process runs once per event and keeps no mapping, so the model works with placeholders for the rest of the session.

### Library callers

A `HookConfig` or `CopilotHookConfig` you build yourself, including the default one, has `RedactToolResults` off, so `HookAdapter.HandleAsync` and `CopilotHookAdapter.HandleAsync` keep the 3.0 behaviour: a secret in a tool result gives the severity decision, `Block` by default. `FromEnvironment` turns redaction on, as the CLIs do, unless `SENTINEL_HOOK_REDACT` is off. A caller that sets `RedactToolResults = true` gets `Allow` with `HookOutput.UpdatedToolOutput` for a redacted tool result and must deliver that output instead of the original. `CopilotHookAdapter.HandleAsync` scans a `userPromptTransformed` prompt without redacting it, because it cannot return a rewritten prompt.

### Placeholder guard

Because the hook CLIs cannot restore a placeholder, a placeholder written into a file or a command would replace the real value. The guard denies such calls on `PreToolUse`:

- on Claude Code, a `Write`, `Edit`, `MultiEdit`, `NotebookEdit` or `Bash` call;
- on Copilot, a `create`, `edit`, `str_replace_editor`, `apply_patch`, `bash`, `powershell`, `write_bash` or `write_powershell` call;

whose input contains text of the exact placeholder shape, such as `[EMAIL_1_k3f9x2]`. The guard does not know which placeholders were minted, so ordinary text of that shape is denied too. The deny reason is fixed text and never echoes the input. `SENTINEL_HOOK_REDACT=off` disables the guard.

## Restoring

This section describes the in-process client. For the MCP proxy, see [Per surface → MCP proxy](#mcp-proxy).

The response scan runs on the reply as the model produced it, still with placeholders. Restoring happens afterwards, so restored values never trigger a response detection.

| Where | Restored |
|---|---|
| Reply text | Yes |
| Tool results in the returned history | Yes |
| Tool-call arguments for PII | Yes, before the tool runs |
| Tool-call arguments for secrets | **Never** |
| The call in a tool approval request | PII yes, secrets **never**, because the call runs once approved |
| Hosted tool calls and their results | As tool-call arguments and tool results |

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
- for **tool-call arguments** in the hook CLIs and the MCP proxy, which judge a call before it runs and cannot rewrite it;
- for the **prompt** on Claude Code `UserPromptSubmit` and Copilot `userPromptSubmitted`, where a command hook cannot rewrite it. Copilot's `userPromptTransformed` can, and is experimental;
- for **MCP content the proxy does not redact**: blob resources, resources whose MIME type is not allowlisted, and content past `SENTINEL_MCP_MAX_SCAN_BYTES`;
- for **personal data in a JSON key**, a **non-string value under a key that names a secret or personal data**, and a **match that spans two JSON members** on the hook CLIs and the MCP proxy;
- when a detector **flags text without spans**.

## Fail closed

In the in-process client, if redaction itself fails, the call fails with a pipeline failure. AI.Sentinel never sends unredacted text there because redaction broke.

The hook CLIs and the MCP proxy cannot fail the host's call, so when redaction fails there, the content is scanned unredacted, as in 3.0, and the detections fall back with `; not redacted`. The exception is not kept, because its message can carry the value.

## The mapping is never stored

In the in-process client, the placeholder to value mapping lives in memory for one `GetResponseAsync` or `GetStreamingResponseAsync` call. It is never logged, audited, forwarded or put in an exception, and it is not shared across calls. Every request is redacted afresh from your history, which holds the real values, with a new tag, so a placeholder from an earlier turn is text in a later one.

The MCP proxy keeps the PII placeholders it minted in memory for the run, so it can [restore them into later tool calls](#mcp-proxy). It keeps no secret values, holds at most 10,000 entries, drops an entry 30 minutes after its last use by default, and never logs or audits the mapping. The hook CLIs keep no mapping at all.

## Audit and notifications

- **One informational audit entry per redacting detector per call**, with `PolicyCode = "REDACTED"`, `Severity = None` and a summary of counts only, such as `Redacted 1 EMAIL, 1 IBAN`.
- The entry is **in the hash chain and forwarded** like any other, so the compliance record is complete. A SIEM sees an informational entry with the `REDACTED` code.
- It **never moves** the severity tiles, the trend, the risk score, the threat metrics or an alert.
- OpenTelemetry logs it at Information.
- The [dashboard](/docs/getting-started/dashboard) shows a "redacted" badge and a "Redacted" filter chip.
- The caller is told through `InterventionAppliedNotification` with `Action = Redact` and the counts. `ThreatDetectedNotification` does not fire for a redaction alone.

## Policies and approvals see real values

Authorization policies and approval requests receive the real argument values, so an approver can judge the actual call. A user-written policy that puts argument values in its deny reason puts them in the audit. Keep values out of deny reasons.
