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
- **Second-stage review** — not a detector type but a second pass over a detector's finding. Set `opts.Reviewer` (an `IDetectionReviewer`), or `opts.EscalationClient` as shorthand for `opts.Reviewer = new LlmJudgeReviewer(client)`; setting both is rejected at `AddAISentinel`. A reviewer can confirm, raise, lower or clear a finding. A finding at `Medium` or above from a rule-based detector that implements `ILlmEscalatingDetector` is reviewed: `SEC-02` CredentialExposure, `SEC-08` EntropyCovertChannel, `SEC-19` ToolCallFrequency, `SEC-23` PiiLeakage and `SEC-32` SystemPromptEcho. Other rule-based detectors are not reviewed. A semantic detector's embedding hit is reviewed too, and so is a text that reaches no bucket but scores at or above its `ReviewThreshold` (default: its Low threshold), so a reviewer can create a `Medium` finding the embeddings alone missed. Until a reviewer confirms it, an embedding hit on a semantic detector is capped at `Medium`, raised to the detector's `SeverityFloor` when one is set. Fast-path regex matches are never capped. `opts.Configure<T>(c => c.CapSemanticSeverity = false)` opts a detector out of the cap; it is still reviewed, and a verdict can lower or clear its finding. A reviewed finding keeps the detector's reason and adds the outcome and the reviewer's reason, such as `Semantic match — high-severity threat pattern — Reviewed: confirmed — <reason>`. Per scan, `opts.MaxReviewsPerScan` (default 4; 0 disables review) limits how many reviews start, and `opts.ReviewTimeout` (default 5 seconds) limits each one; a finding that is not reviewed keeps its capped result. AI.Sentinel warns at startup when a generator is configured, semantic detectors are capped and no reviewer is set.
- **Rule + Semantic ⚠️** — a high-precision rule layer runs first and always, so the unambiguous phrasings are caught with no generator; anything needing context falls through to the semantic path.
- **Stub** — a placeholder with no implementation; always returns `Clean`. Setting `opts.Reviewer` or `opts.EscalationClient` does **not** activate it, because a reviewer only judges findings a detector has already produced.

## What detectors read

By default, every detector reads the same text for a message: its text, followed by the tool calls and tool results it carries, in content order. The rule-based detectors read it through `SentinelContext.TextContent`, and the semantic detectors score it message by message. The detectors listed below as prose-only are the exceptions.

- A tool call reads `tool:{name} input:{arguments}`, with the arguments as compact JSON. The Claude Code and Copilot hooks and the MCP proxy scan a tool call in the same shape, so a detector sees the same text on every surface. When the arguments cannot be serialised as a whole, each one is, and only those that cannot are left out.
- A tool result carried as `FunctionResultContent` reads as its result: a string as it is, a `JsonElement` as its raw text, an `AIContent` or a list of them as the text they carry, anything else as compact JSON. A result that cannot be serialised is left out, and the rest of the scan still runs.
- A hosted tool call or result, of an MCP server, code interpreter, web search or image generation tool, reads as the text it carries: the queries of a web search call, and the text of the inputs or outputs of the others, tool content nested in them included.
- Content reads as text when it is text or text-typed data, such as `text/plain` or `application/json`. Binary data, such as an image, is not read.
- A tool approval request reads as the call it wraps, unless the message also carries that call. With `UseAISentinel()` outside the tool loop, the request is all the scan sees of a call to an approval-required tool, so its arguments are judged before anyone approves it. An approval response is not read: it repeats a call already judged.

**Behaviour change ([#434](https://github.com/MarcelRoozekrans/AI.Sentinel/issues/434)).** In the in-process `IChatClient` pipeline the rule-based detectors used to see neither tool calls nor tool results, because an agent loop carries them as `FunctionCallContent` and `FunctionResultContent` with no message text. They now do, so an application can get findings, and Quarantine blocks, on tool traffic. With redaction on, the default, a secret or personal data in a tool result or in tool-call arguments is redacted instead, a value recognised only by its JSON key included: `{"password":"hunter2"}` reaches the model as `{"password":"[PASSWORD_1_k3f9x2]"}`, and nothing is quarantined. A value that cannot be redacted, such as the number in `{"password": 12345678}`, falls back to the action of its severity, so a credential there still quarantines; see [Fallback](../redaction#fallback). With redaction off, a credential in a tool result is a Critical finding and quarantines the call by default.

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

`SEC-08` EntropyCovertChannel examines each message, newest first, up to 64 KiB of each, so a large file read early cannot push a later message out of the window. `SEC-24` AdversarialUnicode reads tool calls and results too, and ignores the joiners writing systems need: a zero width joiner between emoji, and a zero width non-joiner between Arabic-script or Indic letters. `SEC-32` SystemPromptEcho reads the newest assistant message's text and tool calls, not the hosted tool results in it, which are retrieved content rather than the model's output. For a finding of a rule-based `ILlmEscalatingDetector`, which does not report which text matched, the reviewer is shown the newest message's full text, up to its last 64 KiB; for a semantic candidate it is shown the text that scored. Prompt injection's rule layer still reads only the newest user message's text.

## How semantic detectors score

A semantic detector embeds the text of each message that is new in the scan, compares it by cosine similarity with its High, Medium and Low reference examples, and reports the most severe bucket any message reaches. A message's text is its text plus the results of the tool calls it carries. Redaction placeholders such as `[EMAIL_1_k3f9x2]` are normalised to `[EMAIL]` first.

**Changed in 3.1: each new message is scored on its own.** Semantic detectors used to embed the whole conversation as one text. They now embed each message that is new in the scan, and the most severe match decides. At most 16 texts are embedded per scan: past that, the oldest new texts are joined into one, so none goes unjudged.

- In long conversations the semantic detectors find more, because a short malicious message is no longer diluted by the rest of the chat.
- A finding no longer repeats on every later turn. On the prompt path only the current turn is judged: the messages after the last assistant message. A request that ends in an assistant prefill, such as an opening `{`, still has its user turn judged: the prefill is skipped. A client that resends history without assistant messages still has every message judged.
- On the prompt path, the system prompt from `ChatOptions.Instructions` is scored only on a conversation's first turn, when there is no assistant message yet. `ScanMessagesAsync` scores it on every call.
- Tool results carried as `FunctionResultContent` are scored: a string as it is, a `JsonElement` as its raw text, anything else as compact JSON. A result that cannot be serialised is skipped, and the rest of the scan is still scored. Since [#434](https://github.com/MarcelRoozekrans/AI.Sentinel/issues/434) tool calls are scored too, and the rule-based detectors read the same text; see [What detectors read](#what-detectors-read).
- The public `ScanMessagesAsync` now judges each message of its list separately instead of joining them.
- A pipeline makes one embedding call per scan for the new messages it has not seen, however many semantic detectors it runs; history and repeated tool results hit the embedding cache, and redaction placeholders no longer defeat it.
- Tuning: CMP-01 moves to High 0.50 and Medium 0.42, from 0.44 and 0.39; CMP-02 to Medium 0.56, from 0.48, with High unchanged at 0.58; CMP-03 to High 0.66, from 0.65, with Medium unchanged at 0.55. CMP-04 is unchanged. At the 3.0 values, legitimate requests the thresholds had not been fitted to fired: a fairness report on a photo-tagging model reached High on CMP-01, and a demographics dashboard and an interview transcription request reached Medium, so the compliance detectors are stricter and catch fewer of the evaluated prohibited requests: 7 of 17 at High or Medium on all-MiniLM-L6-v2, down from 9. CMP-03 recall is not improved, at 1 of 7; see [#433](https://github.com/MarcelRoozekrans/AI.Sentinel/issues/433) and the [compliance detectors](./compliance) page.
- `SemanticDetectorBase.GetText` is obsolete. Overriding it raises `CS0672`, and a call such as `base.GetText(ctx)` raises `SENTINEL001`. Move the override to `GetTextsToScore`, or mark it `[Obsolete]`. An existing `GetText` override is still scored.

**Each text is embedded once per scan.** The pipeline merges the texts all its semantic detectors want, embeds each distinct one once in one batch with its own generator, and every detector scores its own texts from those vectors. A named pipeline uses its own generator and caches when it sets them; see [named pipelines](../configuration/named-pipelines). Example phrases are embedded once per generator.

**A rejected input loses only itself.** If the provider rejects one text, the other texts of the scan are still scored. After two single-input failures with no success the endpoint is treated as down and the rest of the scan's texts are skipped. A failure is reported once per scan, not once per detector, and a detector left with nothing to score returns `Clean`. A detector whose example phrases failed to embed still runs its rule layer. The [embedding cache](../configuration/embedding-cache) page has the details.

**Changed in 4.1: SEC-01, SEC-05 and SEC-09 catch paraphrased attacks ([#432](https://github.com/MarcelRoozekrans/AI.Sentinel/issues/432)).** Their examples now describe what an attack asks for instead of one wording of it, and their thresholds come from the same rule as the compliance detectors, set on all-MiniLM-L6-v2. SEC-05's and SEC-09's `ReviewThreshold` sit above what the rule gives, to keep review cost bounded. SEC-01 no longer has Low examples.

| Detector | High | Medium | `ReviewThreshold` | 4.0 High / Medium / `ReviewThreshold` |
|---|---|---|---|---|
| SEC-01 `PromptInjectionDetector` | 0.41 | 0.37 | 0.33 | 0.90 / 0.82 / 0.75, and Low 0.75 |
| SEC-05 `JailbreakDetector` | 0.45 | 0.37 | 0.33 | 0.90 / 0.82 / 0.75 |
| SEC-09 `IndirectInjectionDetector` | 0.47 | 0.45 | 0.35 | 0.90 / 0.82 / 0.75 |

- **Recall.** On held-out paraphrases that no tuning step saw, embeddings alone catch 5, 1 and 0 of 5 at High or above, against 0 of 5 for each detector with the 4.0 values. With an LLM judge they catch 5, 2 and 0 of 5, and the judge cleared every held-out benign candidate.
- **False positives.** No held-out benign text reaches a High set. Without a judge, 2 of 12 held-out benign texts that discuss attacks on AI reach SEC-01's Medium set, a `High` finding: an incident ticket and a scanner report that quote attacks. With the default cap they are reported at `Medium`; a reviewer clears or confirms them. An earlier tuning round put such texts in the High sets, so its held-out texts were folded into the tuning set and the values above were measured on a fresh batch.
- **SEC-09 recall is low.** It catches none of the 5 held-out injections hidden in short tool outputs and files, and none of them reaches `ReviewThreshold`, so a reviewer does not see them either. An injected line inside a long page, review or changelog is also diluted in the embedding of the whole text; [#533](https://github.com/MarcelRoozekrans/AI.Sentinel/issues/533) tracks windowed scoring.
- **Another embedding model needs its own values.** These values are tuned on all-MiniLM-L6-v2; on bge-base-en-v1.5 they fire on almost every text. Run the [evaluation tool](https://github.com/MarcelRoozekrans/AI.Sentinel/blob/main/docs/superpowers/evaluations/2026-10-17-compliance-detectors.md#security-detectors) on your model and set `HighThreshold`, `MediumThreshold` and `ReviewThreshold` from its run with `opts.Configure<T>(c => ...)`.
- **With `CapSemanticSeverity = false`** and no reviewer, a text above the lower thresholds raises an uncapped finding: `Critical` from the High bucket and `High` from the Medium bucket. Any benign text that reaches a High set is then an uncapped `Critical`, and the two held-out benign texts above are uncapped `High` findings. An opted-out detector with a reviewer is still reviewed, and a verdict can lower or clear the finding.

## Second-stage review

An embedding says a text is close to a topic, not that it is an attack. A pipeline therefore treats a semantic detector's hit as a candidate until something confirms it:

- **The cap.** Without a reviewer, an embedding hit is reported at most at `Medium`. If the detector has a `SeverityFloor` above `Medium`, the cap rises to the floor. A fast-path regex match is never capped. Opt a detector out with `opts.Configure<T>(c => c.CapSemanticSeverity = false)`; `null` and `true` cap. An opted-out detector is still reviewed, and a verdict can lower or clear its finding.
- **The reviewer.** Set `opts.Reviewer` to an `IDetectionReviewer`, or `opts.EscalationClient` to a chat client, which is shorthand for `opts.Reviewer = new LlmJudgeReviewer(client)`. Setting both is rejected at `AddAISentinel`. A named pipeline uses its own reviewer and does not inherit the default pipeline's. The reviewer can confirm the proposed severity, raise or lower it, or clear the finding.
- **`ReviewThreshold`.** A text that reaches no bucket is still reviewed when its similarity is at or above the detector's `ReviewThreshold`. The default is its Low threshold; SEC-01, SEC-05 and SEC-09 set their own, see above. Set another with `opts.Configure<T>(c => c.ReviewThreshold = 0.6f)`. It must be in (0, 1] and not above the Medium threshold.
- **The budget.** `opts.MaxReviewsPerScan` (default 4) is the most reviews one scan starts, highest proposed severity first; 0 disables review and a negative value is rejected. `opts.ReviewTimeout` (default 5 seconds) is how long one review may take. A finding that is not reviewed, or whose review fails or times out, keeps its capped result.
- **The warning.** When a generator is configured, no reviewer is set and a semantic detector is capped, AI.Sentinel logs a warning at startup. `DescribeUnreviewedSemanticDetection()` returns the same text for hosts without a logger.

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
