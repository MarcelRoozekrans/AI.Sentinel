# Scan budget: new messages only, MaxScanBytes, timeouts fail closed (#439)

## Why

The in-process `IChatClient` pipeline has no limit on how much text it scans, and two of its limits fail open:

- **Unbounded text.** `SentinelContext.TextContent` joins every message, tool calls and tool results included since #434. `CredentialExposureDetector` and `PiiLeakageDetector` run all their regexes over it; `PlaceholderTextDetector` and `RepetitionLoopDetector` do the same over `ProseContent`; several others loop over every message in `ctx.Messages`.
- **Quadratic rescans.** With `UseAISentinel()` inside a tool loop, the request leg rescans the whole history on every round trip. `NewMessagesFrom` already marks what is new (everything after the last assistant message, `SentinelPipeline.NewFromAfterLastAssistant`), but only the semantic detectors honour it, since #424.
- **Timeouts fail open.** Every regex has a 1000 ms timeout. A `RegexMatchTimeoutException` is caught by `DetectionPipeline.SafeAnalyzeAsync` like any other failure and becomes Clean. A tool result an attacker controls can therefore switch a detector off by making it time out.
- **The MCP cap fails open on the tail.** `SENTINEL_MCP_MAX_SCAN_BYTES` (default 262 144) is one UTF-8 budget per scan: items are taken in order, the first that does not fit is truncated to what is left, and the rest is forwarded unscanned. Text placed after the cap is never judged.

One rule fixes all of it: **text Sentinel could not scan is a finding, not a pass.**

## Goals

1. Built-in detectors that judge content scan only the new messages of a scan. History is judged on the turn it arrives.
2. `SentinelOptions.MaxScanBytes` bounds the UTF-8 bytes the detectors scan per scan, default 262 144, the MCP default.
3. New content over the budget is still scanned up to the budget, and the scan also gets one **Critical** oversize finding.
4. A `RegexMatchTimeoutException` in a detector is a **Critical** finding attributed to that detector, not Clean.
5. The MCP proxy reports the same Critical oversize finding instead of forwarding the unscanned tail silently.
6. Custom detectors get goals 3 and 4 without code changes.

## Non-goals

- Changing what the public `SentinelContext.TextContent` means. Custom detectors keep reading the whole conversation through it; the new text is added beside it.
- Changing other detector failures, such as an embedding endpoint being down. They keep degrading to Clean as documented on `SafeAnalyzeAsync`: an unavailable control must not stop all work. Only a timeout, which content can provoke, fails closed.
- A per-detector budget, or per-message budgets. One budget per scan, as in MCP.
- Changing the response leg's scope; it already scans only the generated message.
- #387 History: a separate PR.

## Anti-goals

- A cap that an attacker can bypass by padding: anything past the cap must surface as a finding.
- A timeout that reads as Clean anywhere: in the pipeline, the hooks, the MCP proxy or `ScreenAsync`.

## Decisions (Marcel, 2026-10-30)

- Oversize content: **finding, fail closed**. Not MCP-style silent truncation, not configurable.
- Severity of both fail-closed findings: **Critical**, so Quarantine under default actions. A host that wants less turns down a timeout per detector with `DetectorConfiguration.SeverityCap`, or raises `MaxScanBytes`.
- `MaxScanBytes` default: **262 144**, the same number as `SENTINEL_MCP_MAX_SCAN_BYTES`.
- MCP proxy: fixed **in the same PR**.
- Release: **`feat:`, 4.2.0**, behaviour change called out in the PR.
- Approach **A**, below.

## Approaches

- **A. Enforce centrally in the pipeline (picked).** `SentinelContext` exposes the new messages' text cut to the budget; `DetectionPipeline` maps a regex timeout to a Critical finding of the detector that threw and adds one Critical oversize finding; detectors still scan the first `MaxScanBytes`, so a real hit there keeps its own detector and evidence in the audit. One place to get right, and custom detectors are covered.
- **B. Enforce per detector.** Each regex detector catches its own timeout and trims its own input. Explicit, but about 15 copies, custom SDK detectors stay fail-open, and the oversize finding needs a pipeline home anyway.
- **A, skipping the scan when oversize.** Cheaper, but the audit would show only "oversize" where it could show the injection that sits in the first 256 KiB.

## Design

### New-messages text on `SentinelContext`

- Add a public, cached, budget-cut text of the new messages: each message from `NewMessagesFrom` on, read with `MessageText`, joined by a single space, the same shape as `TextContent`. A prose-only counterpart replaces the internal `ProseContent` use in `PlaceholderTextDetector` and `RepetitionLoopDetector`.
- The context carries the budget as an init property, set by the pipeline from `SentinelOptions.MaxScanBytes`. Default on a hand-built context: unlimited, so `SentinelContextBuilder` tests behave as today unless they set it.
- The context also exposes whether the new text was cut, which the pipeline reads to add the oversize finding. Cutting happens on a UTF-8 boundary, never inside a surrogate pair.
- `SentinelContextBuilder` gets a `WithMaxScanBytes`, as it has `WithNewMessagesFrom`.

### Which built-in detectors move

Rule: a detector that **judges content** reads only the new messages. A detector whose signal is **a property of the whole conversation** keeps reading `ctx.Messages`.

- Move to new messages: `CredentialExposureDetector`, `PiiLeakageDetector`, `PlaceholderTextDetector`, `RepetitionLoopDetector`, `AdversarialUnicodeDetector`, `WrongLanguageDetector`, `IncompleteCodeBlockDetector`, `TruncatedOutputDetector`, `EntropyCovertChannelDetector`.
- Keep the whole conversation: `ToolCallFrequencyDetector` (counts tool messages), `UnboundedConsumptionDetector` (response-to-prompt ratio), `SystemPromptEchoDetector` and `OutputSchemaDetector` (already read only the last or last assistant message), `BlankResponseDetector`.
- Semantic detectors already score only the new messages. **My call:** the base class's default per-message texts share the scan's one budget, in message order, so the tail past the cap is dropped, and selection such as `MaxMessagesToScore` runs on what is left. A subclass that overrides `GetText` or `GetTextsToScore` keeps its own text, as `TextContent` keeps its meaning; the timeout and oversize findings still cover it.

This list is my reading of the code; the builder confirms each detector against the rule and records any deviation in the plan.

### Timeout fails closed

`DetectionPipeline.SafeAnalyzeAsync` catches `RegexMatchTimeoutException` before the generic catch and returns a Critical `DetectionResult` for that detector, with a reason naming the timeout, such as "Regex timed out; content could not be judged". It is logged and reported through `_onDetectorFailure` with its own wording, "timed out and was flagged Critical", since the detector is not skipped; tests asserting the old wording for other failures are unaffected. The existing Floor/Cap clamp then applies, so `SeverityCap` can turn it down. This also covers a semantic detector's rule layer, which runs inside the same try.

`ArgumentCondition` (approval rules) already handles its own timeout and is out of scope.

### Oversize finding

- After the detectors run, when the context reports the new text was cut, the pipeline adds one Critical finding with a pipeline-owned detector id and a reason giving the scanned and total byte counts. Proposed id: `SEC-00`, listed in the detector docs as "scan limit". **My call**, open to a better name in review.
- It goes through the same action, audit, alert and intervention path as any detection, so hooks, `ScreenAsync` and the in-process client see it without special handling.
- **My call:** it is added after severity clamps, the semantic cap, review and action overrides, so none of them touch it, and per-detector disabling cannot remove it; the only way to avoid it is a larger `MaxScanBytes`. Its action is the configured `OnCritical`.
- The id belongs to no `IDetector`. Tests that enumerate detectors, such as the documentation and registration tests, and `DetectorPresets`, list it as a pipeline id, not a detector. It is documented in the detector reference and mapped in the OWASP table under LLM10 Unbounded Consumption.

### MCP proxy

**My call:** the pipeline is the one place that cuts. The proxy sets `SentinelOptions.MaxScanBytes` from `SENTINEL_MCP_MAX_SCAN_BYTES`, and `MessageBuilder` and `RedactableCollector` stop truncating the scan text themselves: they pass the whole text, and the pipeline cuts it and adds the oversize finding. This needs no new entry point, gives one finding with one byte count, and separators or tool-call framing cannot push trimmed text over a second budget. In the redacting path an item over the budget is no longer forwarded unredacted as "oversize": it is part of the scan and blocks it. Today's oversize stderr line becomes the finding's log. Docs for the variable change from "skipped" to "blocked".

### Options and docs

- `SentinelOptions.MaxScanBytes`, an `int`, default 262 144, validated positive. A named pipeline configures its own `SentinelOptions` from defaults, like every other option, so it gets 262 144 unless it sets its own.
- The hooks read `SENTINEL_HOOK_MAX_SCAN_BYTES`, parsed like `SENTINEL_MCP_MAX_SCAN_BYTES`, so a Claude Code or Copilot host can raise the budget too; without it a hook host would have no way past a block on a large tool result.
- Document in the options reference, the detector list (the new id) and the MCP env var docs.
- Release: **`feat:` → 4.2.0** (Marcel, 2026-10-30), with `MaxScanBytes` as the feature. The PR body and the commit message call out the behaviour change plainly: under default actions, a new turn over 256 KiB, a regex timeout, and an MCP item over the proxy's budget now block where 4.1 let them through; hosts raise `MaxScanBytes` or adjust `OnCritical`/`SeverityCap`.

### Surfaces that mark everything new

`ScreenAsync`, the hook runners, the public `ScanMessagesAsync` and the MCP request leg pass `newMessagesFrom: 0`. That is correct: each already builds its messages from the current event only, a prompt, a tool call or a tool result, not from a transcript. The response leg scans only the generated messages. So the budget applies to exactly one event on those surfaces, and a single event over 256 KiB, a model response included, is Quarantined, as decided.

## Tests

- Timeout: a test detector whose regex times out on crafted input yields Critical, not Clean; `SeverityCap` turns it down.
- Rescan: in a two-round tool loop, a secret in round 1's tool result is flagged once, in round 1, and not again in round 2.
- Budget: new content just under, at, and over `MaxScanBytes` gives no, no, and one oversize finding; a credential inside the first `MaxScanBytes` is still reported by its own detector; a credential past the cap is not, but the scan is Critical.
- UTF-8 cut never splits a surrogate pair.
- MCP: a tool result over the cap is blocked with the oversize finding, in both the redacting and non-redacting paths.
- ComplianceEval numbers unchanged: eval inputs are below the cap and single-turn.

## Left to the builder

- Property and member names on `SentinelContext`.
- The exact reason strings.
- Whether the budget counts the separators between messages.
- How the oversize finding is ordered among the detections.
