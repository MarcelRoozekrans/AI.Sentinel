# Redaction: allow the request, minus the sensitive parts

Issue: #338. Target: the API changes and app-prompt redaction ship in 3.0. The MCP proxy and the hook CLIs follow in 3.1.

## Intent

Today, when `PiiLeakageDetector` or `CredentialExposureDetector` finds personal data or a secret in a prompt, AI.Sentinel can quarantine the call, alert, log or let it through. The only way to keep the data away from the model is to block the whole request, so the user gets nothing.

Redaction adds a more forgiving option. The request goes through, the model gets `[EMAIL_1]` in place of the address, and the user still gets a useful answer. Redact is **not a kind of block**. It means "allow, with the sensitive parts removed", and every surface (docs, dashboard, audit, the caller's code) presents it that way.

Compliance angle: the GDPR's data minimisation (Art. 5(1)(c)) and data protection by design (Art. 25), and the README's EU AI Act Art. 10 row, which moves from "detects" to "detects and keeps it away from the model". Do not overclaim: Art. 10 is mainly about the training, validation and test data of high-risk systems.

## Goals

- A request containing PII or a credential reaches the model with each sensitive value replaced by a numbered, typed placeholder: `[EMAIL_1]`, `[IBAN_1]`, `[API_KEY_1]`.
- The user sees real values. Before the reply returns to the caller, AI.Sentinel puts the original values back in place of the placeholders, so "I drafted a mail to [EMAIL_1]" reaches the user as "I drafted a mail to jan@acme.nl".
- Tool calls get real values. When the model calls a tool with a placeholder in its arguments, for example `send_email(to: "[EMAIL_1]")`, AI.Sentinel swaps the real value back in before the tool runs.
- In 3.0, PII and credential detections redact **by default**.
- The audit log records that a redaction happened, and how many of each type, never the value.
- Redaction never makes things less safe than today. When it can't redact, AI.Sentinel does what it would have done without Redact (see Fallback).

## Non-goals

- Redaction by semantic (embedding) detectors. They can't say where in the text the data is, so they keep their current actions.
- Redacting the model's own output on its way to the user. Redaction protects what goes **to the model**. Anything sensitive the model produces is handled by the response scan, as it is today.
- Checksum validation, such as the Luhn check for card numbers, the IBAN mod-97 or the BSN 11-proef. That is a separate accuracy improvement.
- MCP proxy and hook redaction in 3.0. They come in 3.1 (see Rollout).

## Anti-goals: these would make it a failure even if it works

- An original value reaching the audit store, the dashboard, a forwarder, an alert webhook, a log line or an exception message.
- Configuring Redact causing data to slip through in places that can't redact.
- A redacted request showing up as blocked, quarantined or a threat in the dashboard or the counts.
- Real values reaching the model in a later turn, through conversation history or earlier tool calls.

## Decisions made with the maintainer

1. **Restore in replies:** yes, on by default. A caller can turn it off to keep placeholders in the reply.
2. **Restore in tool-call arguments:** yes, before the tool runs.
3. **Fallback:** when Redact is configured but redaction isn't possible, the detection uses the action its severity maps to, exactly as today, and the audit entry notes that redaction wasn't possible.
4. **Default in 3.0:** `PiiLeakageDetector` and `CredentialExposureDetector` default to Redact. The release notes show the one line that restores the old behaviour.
5. **Scope of 3.0:** every public API change, plus full redaction in the in-process chat client (`SentinelChatClient` / `SentinelPipeline`). The MCP proxy and the hooks build on it in 3.1, with no further breaking change.
6. **Framing:** "allow, minus the sensitive parts", with the compliance angle above, in the README, the website docs and the EU AI Act coverage table.
7. **Audit:** a redaction is informational, not a threat (see Audit and dashboard).

## Design

### The Redact action and per-detector actions

- Add `SentinelAction.Redact`.
- Today an action is chosen only by severity (`OnCritical`, `OnHigh`, `OnMedium`, `OnLow`). Add `SentinelAction? Action` to `DetectorConfiguration`. When it is set, it overrides the severity mapping for that detector, for example `opts.Configure<PiiLeakageDetector>(c => c.Action = SentinelAction.Quarantine)`.
- Setting `OnCritical` or any other severity option to `Redact` is invalid, because only some detectors can redact. Options validation rejects it.
- Setting `Action = Redact` on a detector that can't redact is also rejected by validation, with a message that names the detector.
- The two default-Redact detectors get `Action = Redact` unless the user set something else.

### Detectors that can redact

- Add an interface, for example `IRedactingDetector : IDetector`, with a method that takes one string and returns every sensitive span in it: start, length, and entity type.
- `DetectionResult` is unchanged.
- The pipeline calls this method once per string it may send to the model. That avoids mapping offsets from the joined `SentinelContext.TextContent` back onto individual messages and content parts.
- The redaction is a **pre-pass** on the outbound request (my call):
  1. Collect every string that will be sent to the model:
     - the text of every message, in every role, including the system message and earlier assistant turns;
     - the string values inside `FunctionCallContent` arguments;
     - the string content of `FunctionResultContent`.
  2. Ask each redacting detector whose effective action is Redact for its spans, and replace them.
  3. Run the normal detection pipeline on the redacted request. A PII hit that was redacted no longer fires. Every other detector, such as prompt injection, judges the redacted text, and its own action applies as before. Quarantine from any detector still blocks the call.
- Redacting `FunctionCallContent` and `FunctionResultContent` is required, not optional. Without it, a value restored into a tool call in turn N goes back to the model as conversation history in turn N+1. Today those parts aren't scanned at all, because detectors only see `ChatMessage.Text`.
- LLM escalation does not run in the pre-pass (my call). It exists to cut false positives before blocking. Masking a false positive costs little.

### Seeing every model round trip and every tool call (my call)

`FunctionInvokingChatClient` runs tools and makes the follow-up model calls itself. Where it sits relative to Sentinel in the builder decides what Sentinel can see:

- **Sentinel outside function invocation**, which is the order the README documents: Sentinel sees only the caller's messages and the final reply. A tool would run with `[EMAIL_1]` as its argument, and tool results would reach the model unredacted.
- **Sentinel inside function invocation**: Sentinel sees every model round trip, but a tool call returned by the model is invoked before Sentinel sees the next request.

The design must work in either order:

1. **Tools.** Sentinel wraps each `AIFunction` in `ChatOptions.Tools` before forwarding. The wrapper swaps placeholders in the arguments back to real values just before the inner function runs. It also redacts the function's result before it can reach the model.
2. **The mapping.** The mapping is held in a scope that lives for the whole outer `GetResponseAsync` / `GetStreamingResponseAsync` call. That makes the placeholders in tool calls and later round trips the same ones the first request used, whichever side of function invocation Sentinel sits on.
3. **Shared hook with #359.** Tool-call authorization has the same gap: a denied tool call made by the model still runs. That bug needs the same invocation-time hook, so build one mechanism that serves both. #359 can land first or together with this work.

Audit entries are one per redacting detector per outer call.

### When detectors disagree (my call)

Each detection gets an effective action: its detector's `Action` override if set, otherwise the action for its severity. An override may lower the outcome, for example a Critical credential set to Redact. That is the point of the override.

Across one request:
- If any detection's effective action is Quarantine, the call is quarantined and nothing is redacted or sent.
- Otherwise every Redact detection is redacted. The highest remaining action among the other detections (PassThrough < Log < Alert) applies as it does today.

`InterventionEngine` and the notifications move from one action per request to this rule.

### How the caller learns about a redaction (my call)

Sentinel publishes an `InterventionAppliedNotification` with `Action = Redact`, carrying the counts per type and never values, through the existing mediator channel. `ThreatDetectedNotification` does not fire for a redaction alone. The `ChatResponse` itself is not marked. Nothing throws.

### Placeholders and the mapping

- Placeholder format: `[TYPE_n]`, numbered per type within one request, starting at 1. The same original value gets the same placeholder everywhere in that request.
- Entity types:
  - from `PiiLeakageDetector`: `CREDIT_CARD`, `SSN`, `IBAN`, `BSN`, `NINO`, `PASSPORT`, `TAX_ID`, `EMAIL`, `PHONE`, `DATE_OF_BIRTH`;
  - from `CredentialExposureDetector`: `API_KEY`, `PASSWORD`, `PRIVATE_KEY`, `BEARER_TOKEN`, `AWS_SECRET`, or similar.
  - The builder may adjust the names. They must stay upper case, readable to a model, and documented.
- **The mapping:**
  - lives in memory for one `GetResponseAsync` / `GetStreamingResponseAsync` call and is dropped when the call ends;
  - is never logged, audited, forwarded or put into an exception;
  - is not shared across calls, so numbering may differ between turns. That is fine, because each request is redacted afresh from the caller's history, which holds real values.
- **Amended after the final review:** every placeholder also carries a random tag drawn per call, `[TYPE_n_tag]` such as `[EMAIL_1_k3f9x2]`. With a provider that keeps the conversation and returns a `ConversationId`, only new messages are sent, so the model holds placeholders from earlier calls; with numbering restarting at 1, such a placeholder resolved to whatever value the current call gave the same type and number. A placeholder with another call's tag never resolves and stays text, so placeholder-shaped input needs no reserving or escaping either.
- **Text that already looks like a placeholder:** if the input already contains text in the placeholder format, such as a user literally typing `[EMAIL_1]`, restoring must not turn it into a real value. Only placeholders this request created are restored. The builder picks the mechanism, for example numbering past any existing matches.

### Restoring

- **Order:** the response scan runs on the reply as the model produced it, still with placeholders. Restoring happens afterwards, so restored values never trigger a response detection.
- **Where:** restore in the text content of the response messages and in the string values of `FunctionCallContent` arguments.
- **Streaming:** `GetStreamingResponseAsync` already buffers all updates before returning them. Restoring must handle a placeholder split across two updates (`[EMA` + `IL_1]`).
- **Opt-out:** `SentinelOptions.RestoreRedactedValues`, default true. When false, the reply and tool calls keep the placeholders. The name is the builder's choice.

### Fallback

A detection whose effective action is Redact falls back to its severity's action in these cases:

- **In the response scan.** Redaction only applies to the outbound request.
- **On a surface that can't rewrite.** In 3.0 that means the MCP proxy and the hook CLIs. Their `HookDecision` mapping treats Redact as "use the severity mapping".
- **When the detector flagged the text but returned no spans,** for example because the LLM-escalation path flagged it.

In every case, the audit entry for that detection says redaction was not possible.

### Audit and dashboard (decided: informational, not a threat)

A redaction is evidence for compliance, not a threat signal.

- **Audit entry:** one per redacting detector per outer call, with these fields:
  - the detector's id;
  - `PolicyCode = "REDACTED"`;
  - a `Summary` with counts only, for example `Redacted 1 EMAIL, 1 IBAN`;
  - `Severity = Severity.None`.
- Reuse the existing `AuditEntry` fields. Adding a field means a SQLite schema migration and a hash-chain change, and isn't needed.
- **The entry is in the hash chain and forwarded like any other**, so the compliance record is complete.
- **It must not move:**
  - the dashboard severity tiles;
  - the trend;
  - `ThreatRiskScore`;
  - `SentinelMetrics.Threats` and the `sentinel.scan` span tags;
  - an alert sink or the webhook.
- **The builder checks every consumer** of severity for how it treats `Severity.None`, which today only exists on clean detections and never reaches the store, and adjusts any that would count it. The forwarders pass the entry through: a SIEM sees an informational entry with the `REDACTED` code.
- **The dashboard** lists redaction entries in the feed with their own badge, clearly distinct from detections and blocks, and filterable.
- **A fallback** (redaction not possible) is not a redaction. It is audited as the detection it falls back to, at its real severity, with a note in the summary that redaction was not possible.

### Detector changes needed

- **`PiiLeakageDetector`:**
  - Today it stops at the first match and only reports a bool. It must find every match with its position and type.
  - It must match a bare email address (my call). Today it only matches an email preceded by a capitalised "First Last" name, so the most common case would never be redacted.
  - `AnalyzeAsync` keeps its current detection result for the response scan and the fallback path.
- **`CredentialExposureDetector`:**
  - It must return spans that cover the secret value only, keeping the key name: `api_key=[API_KEY_1]`, not `[API_KEY_1]`. The model then still sees the structure.
  - A PEM private key is redacted from its header to its end marker.
- **Bug, fixed in this work:** `CredentialExposureDetector` currently puts the first 20 characters of the matched secret into `DetectionResult.Reason`, which goes into the audit summary. Reasons must name the type only, never any part of the value.

### Hooks and the MCP proxy, for 3.1

These are not built in 3.0. 3.0 must not block them, and they must be possible without a breaking change. Additions go in as new enum values or as `init` properties on records, never as new positional parameters.

- **MCP proxy:** the proxy sits between an agent and its tools.
  - Tool arguments are not redacted, because a tool needs real values.
  - The data that flows toward the model is the tool **result**, so the proxy redacts the text blocks of results.
  - There is nothing to restore, because the proxy never sees the model's reply.
  - Settle the details in the 3.1 design.
- **Claude Code / Copilot hooks:**
  - Claude Code doesn't route the model's reply through a hook, so restoring there isn't possible.
  - A prompt hook can't rewrite the prompt, so it falls back.
  - What a PreToolUse or PostToolUse hook can rewrite needs checking against the current Claude Code and Copilot hook specs in the 3.1 design.

## Documentation

- **README:**
  - Add Redact to the actions table.
  - Show how to configure per-detector actions.
  - Update the EU AI Act Art. 10 row, and add the GDPR data-minimisation line.
  - Note the 3.0 default change and the one-line opt-out.
- **Website docs:**
  - A page on redaction covering what it does, placeholders, restoring, fallback, what is audited, and that the mapping is never stored.
  - Mention that the hooks and the MCP proxy fall back in 3.0.
- **Release notes:** the commit is `feat!:` with a `BREAKING CHANGE:` footer that explains the new default and how to restore blocking. Don't use nested parentheses in the commit body.

## Left to the builder

- Names: the interface, the option and the placeholder types.
- How placeholders split across streaming updates are handled.
- How placeholder-shaped input is protected from restoring.
- The exact dashboard changes, within the requirements above.
- Splitting the work into tasks and PRs.

## Testing expectations

Cover each of these with a test:
- several values of one type and of mixed types;
- the same value appearing twice;
- restoring in text, in streaming split across updates, and in tool-call arguments;
- conversation history and earlier `FunctionCallContent` / `FunctionResultContent` being redacted;
- a placeholder-looking user input not being restored;
- the opt-out;
- fallback in the response scan;
- quarantine from another detector still winning;
- the default-on behaviour.

Also prove that no original value reaches the audit store, by searching every stored field. Include a regression test that the credential reason no longer contains the secret.
