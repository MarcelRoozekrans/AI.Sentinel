# Redaction in the MCP proxy and the hook CLIs: design

Issue: #364. Target: 3.1.0, with no breaking change. This builds on the redaction design in `docs/superpowers/specs/2026-10-15-redaction-design.md`, where its section "Hooks and the MCP proxy, for 3.1" deferred this work. The maintainer's decisions of 2026-10-21 are marked **(decided)**.

## Why

In 3.0, only in-process apps get "allow, minus the sensitive parts". The Claude Code and Copilot hooks and the MCP proxy fall back to the severity action, and their audit summary ends in `; not redacted`. A tool result such as a `Read` of `.env` or a customer export reaches the model in full, or the whole call is blocked. This is the GDPR data-minimisation and EU AI Act Art. 10 gap the README and the EU AI Act page now document.

## Goals

- Data that flows toward the model through a tool result, a prompt or a resource is redacted wherever the host lets a hook or proxy change it.
- Where a host offers no rewrite, the 3.0 fallback stays: severity action and `; not redacted`.
- No breaking change: additive `init` properties, new enum values and new internal paths only. The pinned hook JSON shapes keep working.

## Non-goals

- Redacting tool **arguments** on their way to a tool. A tool needs real values, so a Redact finding in arguments keeps the severity fallback. This includes secrets in the hooks' PreToolUse for 3.1.
- Restoring placeholders in the user-visible reply on the hook hosts. They have no reply hook.

## Anti-goals

- Never send `permissionDecision: "allow"` just to get a rewrite applied. It would bypass the user's permission prompt.
- Never let a redaction failure silently pass data. Fall back to the 3.0 behaviour.

## Host capabilities (researched 2026-10-21)

Claude Code (https://code.claude.com/docs/en/hooks):
- **PreToolUse `hookSpecificOutput.updatedInput`** replaces a tool's arguments. It only takes effect with `permissionDecision` allow or ask.
- **PostToolUse `hookSpecificOutput.updatedToolOutput`** replaces the result before Claude sees it.
  - It must match the tool's output shape for built-in tools. A value that doesn't match is ignored and the original is used.
  - MCP tool output is not validated.
- **PostToolUse `decision: "block"`** only adds the reason next to the output; Claude still sees the original.
- **UserPromptSubmit** cannot replace the prompt.

Copilot (https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-hooks-reference):
- **preToolUse `modifiedArgs`.**
- **postToolUse `modifiedResult: { resultType: "success", textResultForLlm }`.** The docs say command hooks honour it.
- **userPromptSubmitted `modifiedPrompt`** is SDK-only; command hooks' output is dropped.
- **userPromptTransformed `modifiedTransformedPrompt`** rewrites what the model receives and is stored in history. Command-hook support is unverified.
- **Payload field names.** The camelCase payload uses `toolArgs` and `toolResult: { resultType, textResultForLlm }`. The VS Code format uses `tool_input` and `tool_result`.

## Bugs fixed on the way

1. **Copilot input field names.** `CopilotHookInput` reads `toolInput`/`toolResponse`, which Copilot does not send. Copilot tool scans therefore see empty arguments and no result. Read `toolArgs`/`toolResult` too, and prefer them.
2. **Claude Code wire output.** The Claude Code CLI writes `{"decision":"Allow"}` or `"Warn"`, which are not documented values. On exit 0, JSON that fails validation is a non-blocking error.
   - The CLI writes a Claude Code wire object instead. Allow emits `{}`, or a `hookSpecificOutput` object when there is something to say.
   - **Warn** emits `systemMessage`, so the user sees the warning. The reason used to go to stderr on exit 0, where nobody saw it.
   - Block keeps exit 2 plus stderr.
   - The public `HookOutput` record is unchanged; only the CLI's stdout changes, and only Claude Code reads it. This is a bug fix, so the wire tests that pinned the old CLI output are re-pinned to the documented shape (controller's call).
   - Verify with one live run of `claude -p` with the hook configured.

## Design

### Shared mechanism

- **Redacting path.** Add an internal `SentinelPipeline` method that takes the strings or JSON a host gives. It runs the 3.0 redaction pre-pass with a `RedactionSession` and scans the redacted copy with that session's placeholders exempt. It writes `REDACTED` audit entries and returns the redacted content plus the findings.
- **JSON input.** JSON is redacted leaf by leaf, string values only, so the output shape is kept.
- **Errors and oversize content.** Any redaction error, or content larger than `maxScanBytes`, falls back to the 3.0 behaviour: severity action, `; not redacted`.

### MCP proxy

- **Where it redacts.** Toward the agent:
  - `tools/call` results: `ToolCallInterceptor.InvokeAsync` after `next`, covering text content blocks, embedded text resources and `StructuredContent`.
  - `prompts/get`: `PromptGetInterceptor`, message text and embedded text resources.
  - `resources/read`: `ResourceReadInterceptor`, text contents.
  
  Blob, non-allowlisted MIME types and oversize blocks fall back.
- **The response scan** judges the redacted result. The arguments are redacted in the scan copy only, so a finding in the arguments does not fire twice.
- **Restore (decided).**
  - The proxy keeps one in-memory placeholder mapping for its lifetime, with an idle expiry (default 30 minutes, configurable).
  - It restores **PII** placeholders it minted into later `tools/call` arguments, so lookup-then-act flows work. Secrets are never restored, which matches the 3.0 tool rule.
  - This amends the 3.0 design's "nothing to restore" for the proxy.
  - **Shape (controller's call).**
    - A new internal, thread-safe, proxy-scoped placeholder store holds placeholder to value, plus whether the value may be restored into tool arguments. Reuse `RedactionSession`'s existing PII-versus-secret tool rule.
    - The store has an idle expiry and a size cap that evicts the oldest entries.
    - Each interceptor call still uses its own `RedactionSession`, with its own random tag, and registers the placeholders it mints in the store.
    - Restore into `tools/call` arguments looks placeholders up in the store, so placeholders from several calls and tags restore.
    - `RedactionSession` stays per call. It gains at most a hook to export what it minted.

### Claude Code hooks (`sentinel-hook`)

- **PostToolUse:** exit 0 with `hookSpecificOutput.updatedToolOutput` set to the `tool_response`, with its string leaves redacted. Also set `additionalContext` naming the redacted entity types, as a mitigation for a built-in tool whose rewrite is rejected.
- **PostToolUse Block (decided):** emit `updatedToolOutput` with a body of "withheld by AI.Sentinel: <reason>", so the model never receives the output. This applies to built-in tools whose schema accepts it and to MCP tools; where the host rejects the shape, the reason stays as context.
- **PreToolUse placeholder guard (decided):** deny `Write`, `Edit`, `MultiEdit`, `NotebookEdit` and `Bash` input that contains a Sentinel placeholder (`[TYPE_n_tag]` shape). The reason tells the model the value was redacted and must not be written.
  - This is a deny, which needs no `allow`.
  - Other PreToolUse Redact findings keep the fallback.
- **UserPromptSubmit:** fallback.

### Copilot hooks (`sentinel-copilot-hook`)

- **postToolUse:** `{"modifiedResult":{"resultType":"success","textResultForLlm":"<redacted>"}}`. A Block withholds the result with the same "withheld" body.
- **preToolUse:** the same placeholder guard, for Copilot's write and shell tools. Look up its tool names.
- **userPromptTransformed (decided):**
  - Add a new `CopilotHookEvent.UserPromptTransformed` value and CLI verb `user-prompt-transformed`. It emits `{"modifiedTransformedPrompt":"<redacted>"}`.
  - The docs call it supported only after a live check with the Copilot CLI. Until then it is marked experimental.
  - Replies are not restored.
- **userPromptSubmitted:** fallback.

### Chat client: hosted tool contents

- `RedactionSession.MapContent` handles `McpServerToolCallContent`/`McpServerToolResultContent`, the code-interpreter, web-search and image-generation call and result contents, and approval contents typed `ToolCallContent`.
- Restore follows the tool rule.
- `website/docs/redaction.md` approval bullet: "the function call inside a tool approval request or response".

### Configuration

- `HookConfig` / `CopilotHookConfig`: `bool RedactToolResults { get; init; } = true`, from the env var `SENTINEL_HOOK_REDACT`, which accepts on or off.
- MCP: `SENTINEL_MCP_REDACT`, falling back to the hook variable, as the compliance switches do.
- MCP restore idle expiry: `SENTINEL_MCP_REDACT_TTL_MIN`.

### Public additions (all additive)

- **`HookOutput`:** add `UpdatedToolOutput` (JsonElement?) and `Redactions` (counts by type), init-only and ignored when null. Nothing is removed. A prompt rewrite and input rewrite are not added, because no surface uses them.
- **`CopilotHookInput`:** `ToolArgs`, `ToolResult` and `TransformedPrompt`.
- **`CopilotHookEvent.UserPromptTransformed`.**
- **Config properties as above.**

## Audit and report

`REDACTED` entries are written with the CLI or proxy `Source`, so the Art. 10 section of `sentinel report` counts hook and proxy redactions. Fallback entries keep `; not redacted`. The report's Art. 10 empty-section note and the docs that say the CLIs do not redact are updated.

## Docs

- Update `redaction.md` with a per-surface table.
- Update the integrations pages for Claude Code, Copilot and the MCP proxy.
- Update the EU AI Act page and README Art. 10 row: drop the "in-process only" caveat and state the remaining limits.

## Testing

- Unit tests per surface, built on the pinned wire JSON.
- An MCP proxy test with a fake server returning PII and a secret: the agent sees placeholders, and a later call gets the PII restored but not the secret.
- Hook CLI process tests on the stdin/stdout JSON.
- Live checks, recorded in the PR:
  - `claude -p` with the hook for PostToolUse `updatedToolOutput` and the `{}` allow output;
  - Copilot CLI `userPromptTransformed`, if it is available.
