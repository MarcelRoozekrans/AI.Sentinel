---
sidebar_position: 1
title: Overview
---

# Detector overview

AI.Sentinel ships with **60 built-in detectors** across four categories:

| Category | Count | Purpose |
|---|---|---|
| [**Security**](./security) | 32 | Prompt injection, jailbreaks, PII / credential leakage, covert channels, indirect injection, RAG poisoning |
| [**Hallucination**](./hallucination) | 9 | Phantom citations, fabricated authorities, contradictions, stale knowledge, confidence decay |
| [**Operational**](./operational) | 15 | Repetition loops, blank responses, truncated output, language switches, persona drift, sycophancy |
| [**Compliance**](./compliance) | 4 | Requests for practices the EU AI Act prohibits in Art. 5: social scoring, emotion recognition at work or school, sensitive biometric categorisation, crime prediction from profiling. **Off by default**; enable with `opts.EnableComplianceDetectors()` |

The 56 Security, Hallucination and Operational detectors run by default; the 4 Compliance detectors are opt-in.

## Detector modes

Every detector falls into one of these execution modes:

- **Rule-based** — fast regex or heuristic. Always active. Sub-microsecond per call.
- **Semantic ⚠️** — uses embedding cosine similarity via `IEmbeddingGenerator`. Language-agnostic. **Returns `Clean` on every scan until `opts.EmbeddingGenerator` is configured.** The ⚠️ marks a detector inactive in a default install. The CLIs and MCP proxy enable it with `SENTINEL_EMBEDDING_ENDPOINT` and `SENTINEL_EMBEDDING_MODEL`.
- **LLM escalation** — not a detector type but a second pass: when `opts.EscalationClient` is set, a finding already at `Medium` or above is re-classified by an LLM. It upgrades or downgrades an existing finding; it cannot create one.
- **Rule + Semantic ⚠️** — a high-precision rule layer runs first and always, so the unambiguous phrasings are caught with no generator; anything needing context falls through to the semantic path.
- **Stub** — a placeholder with no implementation; always returns `Clean`. Setting `opts.EscalationClient` does **not** activate it, because escalation only re-classifies findings a detector has already produced.

## What detectors read

By default, every detector reads the same text for a message: its text, followed by the tool calls and tool results it carries, in content order. The rule-based detectors read it through `SentinelContext.TextContent`, and the semantic detectors score it message by message. The detectors listed below as prose-only are the exceptions.

- A tool call reads `tool:{name} input:{arguments}`, with the arguments as compact JSON. The Claude Code and Copilot hooks and the MCP proxy scan a tool call in the same shape, so a detector sees the same text on every surface. When the arguments cannot be serialised as a whole, each one is, and only those that cannot are left out.
- A tool result carried as `FunctionResultContent` reads as its result: a string as it is, a `JsonElement` as its raw text, an `AIContent` or a list of them as the text they carry, anything else as compact JSON. A result that cannot be serialised is left out, and the rest of the scan still runs.
- A hosted tool call or result, of an MCP server, code interpreter, web search or image generation tool, reads as the text it carries: the queries of a web search call, and the text of the inputs or outputs of the others, tool content nested in them included.
- Content reads as text when it is text or text-typed data, such as `text/plain` or `application/json`. Binary data, such as an image, is not read.
- A tool approval request reads as the call it wraps, unless the message also carries that call. With `UseAISentinel()` outside the tool loop, the request is all the scan sees of a call to an approval-required tool, so its arguments are judged before anyone approves it. An approval response is not read: it repeats a call already judged.

**Behaviour change ([#434](https://github.com/MarcelRoozekrans/AI.Sentinel/issues/434)).** In the in-process `IChatClient` pipeline the rule-based detectors used to see neither tool calls nor tool results, because an agent loop carries them as `FunctionCallContent` and `FunctionResultContent` with no message text. They now do, so an application can get findings, and Quarantine blocks, on tool traffic. With redaction on, the default, a secret or personal data in a tool result is redacted instead; with it off, a credential in a tool result is a Critical finding and quarantines the call by default.

### Builder order and tool traffic

Where Sentinel sits relative to `UseFunctionInvocation()` decides when tool traffic is judged. In a `ChatClientBuilder` the first `Use` is the outermost client.

- **Inside the tool loop**, with `UseFunctionInvocation()` before `UseAISentinel()`: each model round trip is scanned, so a tool result is judged before the model sees it and a tool call before the tool runs.
- **Outside it**, with `UseAISentinel()` first: the request and the whole loop's response are scanned once, so tool traffic is judged after the loop, when the model has seen the results and the tools have run.

When tool traffic must be judged before the model sees it or before a tool runs, put Sentinel inside the loop:

```csharp
IChatClient client = new ChatClientBuilder(innerClient)
    .UseFunctionInvocation()
    .UseAISentinel()
    .Build(services);
```

Redaction works in either order, as [Redaction](../redaction#tool-calls) describes: a tool result is redacted before the model sees it wherever Sentinel sits. That holds for redaction only, not for findings and the actions they trigger.

### Prose-only detectors

Some detectors read only the messages' text, because tool traffic would distort what they measure: `OPS-01` BlankResponse, `OPS-02` RepetitionLoop, `OPS-03` IncompleteCodeBlock, `OPS-04` PlaceholderText, `OPS-09` TruncatedOutput, `OPS-11` UnboundedConsumption, `OPS-15` WrongLanguage and `SEC-29` OutputSchema. A tool polled until it is done repeats its result, and a file read by a tool can hold a `TODO`; neither is a fault in the model's output.

`SEC-08` EntropyCovertChannel examines each message, newest first, up to 64 KiB of each, so a large file read early cannot push a later message out of the window. `SEC-24` AdversarialUnicode reads tool calls and results too, and ignores the joiners writing systems need: a zero width joiner between emoji, and a zero width non-joiner between Arabic-script or Indic letters. `SEC-32` SystemPromptEcho reads the newest assistant message's text and tool calls, not the hosted tool results in it, which are retrieved content rather than the model's output. LLM escalation shows the classifier the newest message's full text, up to its last 64 KiB. Prompt injection's rule layer still reads only the newest user message's text.

## How semantic detectors score

A semantic detector embeds the text of each message that is new in the scan, compares it by cosine similarity with its High, Medium and Low reference examples, and reports the most severe bucket any message reaches. A message's text is its text plus the results of the tool calls it carries. Redaction placeholders such as `[EMAIL_1_k3f9x2]` are normalised to `[EMAIL]` first.

**Changed in 3.1: each new message is scored on its own.** Semantic detectors used to embed the whole conversation as one text. They now embed each message that is new in the scan, and the most severe match decides. At most 16 texts are embedded per scan: past that, the oldest new texts are joined into one, so none goes unjudged.

- In long conversations the semantic detectors find more, because a short malicious message is no longer diluted by the rest of the chat.
- A finding no longer repeats on every later turn. On the prompt path only the current turn is judged: the messages after the last assistant message. A request that ends in an assistant prefill, such as an opening `{`, still has its user turn judged: the prefill is skipped. A client that resends history without assistant messages still has every message judged.
- On the prompt path, the system prompt from `ChatOptions.Instructions` is scored only on a conversation's first turn, when there is no assistant message yet. `ScanMessagesAsync` scores it on every call.
- Tool results carried as `FunctionResultContent` are scored: a string as it is, a `JsonElement` as its raw text, anything else as compact JSON. A result that cannot be serialised is skipped, and the rest of the scan is still scored. Since [#434](https://github.com/MarcelRoozekrans/AI.Sentinel/issues/434) tool calls are scored too, and the rule-based detectors read the same text; see [What detectors read](#what-detectors-read).
- The public `ScanMessagesAsync` now judges each message of its list separately instead of joining them.
- Each semantic detector makes one embedding call per scan for the new messages it has not seen; history and repeated tool results hit the embedding cache, and redaction placeholders no longer defeat it.
- Tuning: CMP-01 moves to High 0.50 and Medium 0.42, from 0.44 and 0.39; CMP-02 to Medium 0.56, from 0.48, with High unchanged at 0.58; CMP-03 to High 0.66, from 0.65, with Medium unchanged at 0.55. CMP-04 is unchanged. At the 3.0 values, legitimate requests the thresholds had not been fitted to fired: a fairness report on a photo-tagging model reached High on CMP-01, and a demographics dashboard and an interview transcription request reached Medium, so the compliance detectors are stricter and catch fewer of the evaluated prohibited requests: 7 of 17 at High or Medium on all-MiniLM-L6-v2, down from 9. CMP-03 recall is not improved, at 1 of 7; see [#433](https://github.com/MarcelRoozekrans/AI.Sentinel/issues/433) and the [compliance detectors](./compliance) page.
- `SemanticDetectorBase.GetText` is obsolete. Overriding it raises `CS0672`, and a call such as `base.GetText(ctx)` raises `SENTINEL001`. Move the override to `GetTextsToScore`, or mark it `[Obsolete]`. An existing `GetText` override is still scored.

The semantic layers of SEC-01, SEC-05 and SEC-09 miss paraphrased injections on local embedding models; that is tracked in [#432](https://github.com/MarcelRoozekrans/AI.Sentinel/issues/432).

## Severity model

Each detector returns a `DetectionResult` carrying a `Severity` (`None`, `Low`, `Medium`, `High`, `Critical`) and a reason string. The pipeline aggregates per-detector severities into a [Threat Risk Score](../core-concepts/severity-model) (0–100) that drives the [Intervention Engine](../core-concepts/intervention-engine).

## Detector ID convention

Built-in detectors use four prefixes:

- `SEC-NN` — security
- `HAL-NN` — hallucination
- `OPS-NN` — operational
- `CMP-NN` — compliance

Custom detectors authored via [`opts.AddDetector<T>()`](../custom-detectors/sdk-overview) **must** use a different prefix to avoid collisions with future official detectors. Examples: `ACME-01`, `MYORG-CUSTOM-01`.

## Tuning

Every detector — built-in or custom — can be disabled or have its severity output clamped via [`opts.Configure<T>(c => ...)`](../configuration/fluent-config). Floor and Cap apply only to firing results; Clean results pass through unchanged.

```csharp
opts.Configure<WrongLanguageDetector>(c => c.Enabled = false);
opts.Configure<JailbreakDetector>(c => c.SeverityFloor = Severity.High);
opts.Configure<RepetitionLoopDetector>(c => c.SeverityCap = Severity.Low);
```

## Where to next

- [Security detectors](./security) — 32 detectors
- [Hallucination detectors](./hallucination) — 9 detectors
- [Operational detectors](./operational) — 15 detectors
- [Compliance detectors](./compliance) — 4 detectors
- [Writing a custom detector](../custom-detectors/writing-a-detector) — IDetector contract + the SDK
