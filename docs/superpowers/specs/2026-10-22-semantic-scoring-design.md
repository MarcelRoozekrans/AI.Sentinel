# Semantic scoring of new messages: design

Issue: #424. Target: 3.1.0. The maintainer made two decisions on 2026-10-22, marked **(decided)** where they apply.

## Why

`SemanticDetectorBase` embeds `ctx.TextContent`, which is every message in the context joined by spaces. That causes four problems.

1. **Dilution.** One injected or prohibited request in a long conversation is averaged with everything around it, so its similarity drops below the threshold. The longer the chat, the weaker the detection.
2. **Mismatch with tuning.** The thresholds were tuned with `tools/AI.Sentinel.ComplianceEval`, which scores single phrases. At runtime the detectors judge whole conversations, which is a different score distribution.
3. **Random tags change the score.** Redaction placeholders such as `[EMAIL_1_k3f9x2]` carry a random tag per call. The tag changes the embedding and defeats the embedding cache, which is keyed by exact text.
4. **No cache hits.** The joined text is new every turn, so every scan is a cache miss and a fresh embedding call.

## Goals

- **(decided)** A semantic detector scores what is new in the scan, one message at a time. The highest-scoring message decides the severity.
- Placeholders are normalised before embedding, so redaction does not change a score.
- The runtime scoring basis matches the one used for tuning: one message is one phrase.
- **(decided)** Re-tune the compliance detectors CMP-01 to CMP-04 against the real model with the evaluation tool, and improve CMP-03's recall with better examples. Spot-check the security detectors with the same tool, without re-tuning all of them.

## Non-goals

- Joining an attack that is split across turns. Scoring each message on its own does not do this, and neither did the old joined text in any reliable way.
- Changing non-semantic detectors. PII, credentials, the operational detectors and the rest keep reading `TextContent` and `Messages` as today.
- Changing the rule fast path. It already judges only the newest user message.

## Anti-goals

- An early bad message must not re-fire on every later turn. That is the reason the rule layer looks at the newest message only.
- Cost must not grow with conversation length.

## Design

### What is new

`SentinelContext` gains an init property, `int NewMessagesFrom`, with a default of 0. Messages from that index onward are new for this scan. `BuildContext` sets it per path:

| Path | Messages in the context | New from |
|---|---|---|
| Pipeline prompt scan, streaming and not | The caller's history, with `Instructions` as a leading System message | After the last `Assistant` message that precedes the latest non-assistant message: the trailing user and tool messages of this turn. A trailing assistant prefill is skipped first. 0 when there is no such assistant message. |
| Pipeline response scan | The response messages only | 0: all of it is new |
| `ScanMessagesAsync` and its internal wrappers, used by the hooks and the MCP proxy without redaction | The caller's list | The caller passes the index. The default is 0, so the public API judges every message of the list it was given, and `ChatOptions.Instructions` too. A non-zero index is shifted past the instructions message. |
| Host redaction path, `RedactAndScanAsync` | Context, then content items, then unredactable items | `Context.Count`: only the content is new |
| MCP tools/call response without redaction | `[User request, Assistant result]` | 1 |
| Claude Code and Copilot PostToolUse without redaction | `[User tool call, Assistant result]` | 1 |
| `sentinel scan` replay | As the pipeline | As the pipeline |

### How a semantic detector scores

- **Which messages.** Take the messages from `NewMessagesFrom` onward that have non-blank text, without duplicates, 16 at most, so cost stays bounded. Past 16, the oldest are joined with a newline into the first input, so none goes unjudged.
- **Normalise.** Replace each placeholder, `PlaceholderFormat.Pattern()`, with `[TYPE]`.
- **Score.** Embed each message through the existing cache, compute its maximum similarity against the High, Medium and Low example vectors, and report the most severe level any message reaches.
- **`GetText`.** It stays as a virtual hook, but its default is no longer used for scoring. Add `protected virtual IEnumerable<string> GetTextsToScore(SentinelContext ctx)` for detectors that want a specific role. Mark `GetText` obsolete, and don't remove it, because 3.1 is not breaking. No built-in detector overrides `GetText`.
- **Fast path.** Unchanged.
- **Reason text.** Unchanged: it still never quotes the message.

### Cache

Per-message keys mean history messages and repeated tool results hit the existing `InMemoryLruEmbeddingCache`. Normalising placeholders makes redacted text cacheable.

### Re-tuning (decided)

- `ComplianceEval` already feeds single-message contexts, so its verdicts stay comparable. Add a check that a multi-message context scores the same as the strongest single message.
- Re-run it with all-MiniLM-L6-v2 and the bge-base cross-check. Keep or adjust the CMP thresholds based on the results, and record them in the evaluation document.
- **CMP-03 recall.** Add and refine example phrases until recall improves without new false positives on the everyday set. Report the before and after numbers.
- **Security detectors.** Spot-check SEC-01, SEC-05 and SEC-09 with a small labelled set of injection phrases and benign phrases, and report the numbers. Retune them only if a threshold is clearly wrong; anything larger goes into an issue.

### Configuration

None for now. The 16-message cap is a constant. It becomes an option only if someone needs it.

## Behaviour changes for the release notes

- In long conversations the semantic detectors find more, because a short malicious message is no longer diluted.
- A finding no longer repeats on every later turn of a conversation that once contained it. On the prompt path only the current turn is judged.
- The public `ScanMessagesAsync` now judges each message of the list separately instead of joining them.
- Each scan makes more embedding calls, one per new message, but cache hits on repeated text offset this.

## Testing

- **Dilution:** a malicious message within a long benign history still fires.
- **No re-fire:** an old malicious message followed by a benign new turn is clean on the prompt path.
- **Response path:** each response message is scored.
- **Placeholder normalisation:** the same text with different tags embeds once.
- **Cap:** at most 16 inputs are embedded; past that, the oldest new texts are joined into the first input.
- **MCP and hooks:** the result message is judged and the repeated request message is not.
- **Evaluation:** the single-message and the multi-message checks.

## Calls made after the builder check (controller's calls)

- **Scope across detectors.** One rule applies to all semantic detectors and is implemented in the base class. No detector is changed individually. In an agent loop, a user request is judged on the turn it arrives; later turns judge only the new tool results.
- **Empty new range.** It is Clean. A history ending in an assistant prefill is not empty: the prefill is skipped and the user turn before it is new. A client that resends history with no assistant message gets every message scored, from index 0.
- **The index is internal.** The public `ScanMessagesAsync` keeps its signature and judges every message of its list. Only the internal wrappers used by the hooks and the MCP proxy take a new-from index. An out-of-range index is clamped.
- **Fast path.** It is unchanged on every path, MCP and PostToolUse included. There, the newest message is not from the user, so the rule layer stays silent, as it does today.
- **Placeholder normalisation.** It runs in the base class for every semantic detector. The embedding cache is keyed by the normalised text. The example embedding cache is not affected.
- **Acceptance rule for re-tuning.** This is the 3.0 evaluation's rule: no everyday prompt at High, the margins reported, and both models compared. The phrase sets may grow. New phrases are marked as such, and the in-sample caveat stays. Threshold changes ship in 3.1 as tuning and are listed in the release notes.
- **Multi-message check.**
  - Unit tests with the fake generator cover dilution, re-fire, the cap and normalisation.
  - The evaluation tool adds a pass that places each compliance phrase as the last message after a fixed benign history of everyday prompts. The detector must give the same verdict as for the phrase on its own.
- **Model weights.** They download from Hugging Face. This environment reaches it, and the model cache from the 3.0 evaluation is in `~/.cache/ai-sentinel/models`.
