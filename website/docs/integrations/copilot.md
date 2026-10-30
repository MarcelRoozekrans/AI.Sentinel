---
sidebar_position: 2
title: GitHub Copilot
---

# GitHub Copilot integration

`AI.Sentinel.Copilot.Cli` is a native hook adapter for GitHub Copilot's hook system. Same shape as the [Claude Code adapter](./claude-code) — different config file, slightly different hook event names.

## Install

```bash
dotnet tool install -g AI.Sentinel.Copilot.Cli
```

The CLI installs as `sentinel-copilot-hook` on your `PATH`.

## Wire it into Copilot

Add to your repo's `hooks.json` (per Copilot hook documentation):

```json
{
  "version": 1,
  "hooks": {
    "userPromptSubmitted": [
      { "type": "command", "bash": "sentinel-copilot-hook user-prompt-submitted", "timeoutSec": 10 }
    ],
    "userPromptTransformed": [
      { "type": "command", "bash": "sentinel-copilot-hook user-prompt-transformed", "timeoutSec": 10 }
    ],
    "preToolUse": [
      { "type": "command", "bash": "sentinel-copilot-hook pre-tool-use", "timeoutSec": 10 }
    ],
    "postToolUse": [
      { "type": "command", "bash": "sentinel-copilot-hook post-tool-use", "timeoutSec": 10 }
    ]
  }
}
```

Four hook points:

| Hook | Verb | When it fires | What gets scanned |
|---|---|---|---|
| `userPromptSubmitted` | `user-prompt-submitted` | Every user message | The prompt text |
| `userPromptTransformed` | `user-prompt-transformed` | After Copilot transforms the prompt, before the model gets it. **Experimental**, see [Prompt enforcement](#prompt-enforcement) | The transformed prompt, or the prompt when there is none |
| `preToolUse` | `pre-tool-use` | Before any tool call | Tool name + arguments (`toolArgs`) |
| `postToolUse` | `post-tool-use` | After every tool call | Tool result text (`toolResult`) |

Wiring both prompt verbs scans the prompt twice, so without an embedding endpoint the warning that semantic detection is inert may be printed twice.

**Fixed in 3.1: arguments and results are read.** Copilot sends `toolArgs` and `toolResult`. Earlier versions read `toolInput` and `toolResponse` instead, so tool scans saw empty arguments and no result. `toolArgs` is now read whether Copilot sends it as an object or as a JSON string. The old names are still accepted, and the documented names win when both are sent.

**PascalCase event names.** A hook configured with a PascalCase event name, such as `PostToolUse`, gets the VS Code compatible payload, with `session_id`, `tool_name`, `tool_input` and `tool_result`. The hook reads that format too, and the [placeholder guard](#redaction) then checks the Claude Code tool names as well as the Copilot ones. Whether Copilot honours the hook's output for that configuration is not verified yet.

The `timeoutSec: 10` is recommended — gives the hook plenty of headroom even on a cold start with semantic detection enabled. Lower it (2–3 seconds) once you've validated steady-state latency on your hardware.

## Severity → action

Same shared env-var contract as Claude Code:

| Variable | Default | Values |
|---|---|---|
| `SENTINEL_HOOK_ON_CRITICAL` | `Block` | `Block` / `Warn` / `Allow` |
| `SENTINEL_HOOK_ON_HIGH` | `Block` | `Block` / `Warn` / `Allow` |
| `SENTINEL_HOOK_ON_MEDIUM` | `Warn` | `Block` / `Warn` / `Allow` |
| `SENTINEL_HOOK_ON_LOW` | `Allow` | `Block` / `Warn` / `Allow` |
| `SENTINEL_HOOK_VERBOSE` | `false` | `1` / `true` / `yes` → grep-friendly stderr diagnostic |
| `SENTINEL_HOOK_SUPPRESS_SEMANTIC_WARNING` | `false` | `1` / `true` / `yes` → suppress the startup warning that semantic detection is inert. Set only after accepting that SEC-01 and SEC-05 will not fire |
| `SENTINEL_HOOK_REDACT` | `on` | `off` / `0` / `false` / `no` → turn off [redaction](#redaction) of tool results and the transformed prompt, and the placeholder guard. Anything else, or unset, keeps them on |
| `SENTINEL_HOOK_COMPLIANCE` | `off` | `on` / `1` / `true` / `yes` → run the four Art. 5 [compliance detectors](../detectors/compliance), which are off by default. Their findings warn instead of following `SENTINEL_HOOK_ON_HIGH`. Needs `SENTINEL_EMBEDDING_ENDPOINT`. Thresholds are code-only |
| `SENTINEL_HOOK_DETECTORS` | `security` | `security` → the [security preset](./mcp-proxy#detector-profiles) the MCP proxy uses: 16 security detectors plus the four Art. 5 compliance detectors, which run only with `SENTINEL_HOOK_COMPLIANCE=on`. `all` → every detector, including the operational and hallucination detectors that judge a model's reply and fire on tool output, see [Claude Code → Detectors](./claude-code#detectors). Anything else, or unset, keeps `security` |
| `SENTINEL_HOOK_MAX_SCAN_BYTES` | `262144` | A positive integer → the scan budget, `SentinelOptions.MaxScanBytes`, in UTF-8 bytes. An event over it, such as a large tool result, is blocked as [`SEC-00`](../detectors/overview#scan-budget-and-sec-00) under the default `SENTINEL_HOOK_ON_CRITICAL=Block`; raise it to scan more. Anything else, or unset, keeps the default |
| `SENTINEL_EMBEDDING_ENDPOINT` | — | Full embeddings URL, e.g. `https://api.openai.com/v1/embeddings` or `http://localhost:11434/v1/embeddings`. Enables semantic detection |
| `SENTINEL_EMBEDDING_MODEL` | — | Model identifier, e.g. `text-embedding-3-small` or `nomic-embed-text` |
| `SENTINEL_EMBEDDING_API_KEY` | — | Bearer token. Omit for local servers that need none |
| `SENTINEL_EMBEDDING_DIMENSIONS` | — | Vector length, when the model allows a choice |
| `SENTINEL_EMBEDDING_CACHE_DIR` | per-user cache dir | Where reference vectors are cached. Must not be world-writable — see below |
| `SENTINEL_REVIEW_ENDPOINT` | — | Full chat completions URL of the second-stage reviewer, e.g. `https://api.openai.com/v1/chat/completions` or `http://localhost:11434/v1/chat/completions`. Without a reviewer, semantic detections are capped at Medium and only warn |
| `SENTINEL_REVIEW_MODEL` | — | Model identifier of the reviewer. Required with the endpoint |
| `SENTINEL_REVIEW_API_KEY` | — | Bearer token. Omit for local servers that need none |
| `SENTINEL_REVIEW_MAX_PER_SCAN` | `4` | Reviews per scan. `0` turns the review off |
| `SENTINEL_REVIEW_TIMEOUT_MS` | `3000` | Per-review timeout in milliseconds. The hooks default to 3 s because they run on your critical path |

**What the review endpoint receives.** `SENTINEL_REVIEW_ENDPOINT` is sent each flagged text, up to its last 64 KiB. That text can contain the secret or personal data a credential or PII detector flagged, just as the embedding endpoint receives the texts it embeds, so choose a provider you would trust with that data, or a local one. The reviewer's reason comes back the other way: it becomes part of the finding's reason, which the hook's block or warning text passes on to the model. It is sanitised to one line and capped at 200 characters.

What each action does:

- **`Block` on `preToolUse`** → the hook exits 2 with the reason on stderr. Copilot surfaces the call as blocked.
- **`Block` on `userPromptSubmitted`** → the hook exits 2 with the reason on stderr, but this is advisory: Copilot shows it as a warning and drops the hook's output. See [Prompt enforcement](#prompt-enforcement).
- **`Block` on `postToolUse` or `userPromptTransformed`** → exit 0 with the reason on stderr. The tool result or the prompt is withheld: the model gets `withheld by AI.Sentinel: <reason>` in its place, through `modifiedResult` or `modifiedTransformedPrompt`. This holds also with `SENTINEL_HOOK_REDACT=off`.
- **`Warn`** → exit 0 with the reason on stderr (visible in Copilot's log).
- **`Allow`** → exit 0, with `{"decision":"Allow","reason":null}` on stdout.

## When the hook itself fails

The hook fails closed on `preToolUse`. When it cannot evaluate a tool call, it blocks the call with exit 2 and a reason that starts with `Sentinel internal error:` on stderr. This covers:

- a `SENTINEL_APPROVAL_CONFIG` that cannot be loaded or fails validation: `Sentinel internal error: approval config '<path>' could not be loaded: <message>`. Without this, one typo in the file would turn off every approval rule;
- an unexpected exception in the hook, for example an approval database that cannot be opened: `Sentinel internal error: <ExceptionType>: <message>`;
- input without a `toolName` or `tool_name`, while `SENTINEL_APPROVAL_CONFIG` has approval rules: `Sentinel internal error: PreToolUse input has no tool name`. Such a call cannot be checked against the rules. Without approval rules it is scanned as before;
- stdin that is empty or not valid JSON: `Sentinel internal error: malformed stdin JSON: <message>`, or `Sentinel internal error: empty stdin JSON: <message>` when stdin is the JSON `null`.

Tool calls stay blocked for as long as the cause persists. Fix the config file, or unset `SENTINEL_APPROVAL_CONFIG` to run without approval rules. The block is recorded in the [audit file](#audit-destination) as an `AUTHZ-DENY` entry with the code `internal_error` and the policy name `sentinel-internal`; when the input names no tool, the entry has the tool `unknown`, and for unreadable stdin also a new session id. If the hook times out or is killed, Copilot does not treat that as a block: that behaviour belongs to Copilot, not to Sentinel.

On `userPromptSubmitted`, `userPromptTransformed` and `postToolUse` the same failures exit 1 with the error on stderr, which Copilot does not treat as a block. A detector that fails, for example because the embedding endpoint is down, does not block on any event: it is skipped for that scan, reported on stderr, and the other detectors still run.

## Redaction

With `SENTINEL_HOOK_REDACT` on, the default, the hook redacts personal data and secrets where Copilot lets a command hook rewrite content:

- **`postToolUse`** redacts the tool result's `textResultForLlm` and returns it as `modifiedResult`, so the model sees `[EMAIL_1_k3f9x2]` in place of the address. A result without a string `textResultForLlm` is scanned as before and not redacted. `modifiedResult` must have `resultType: "success"`, because `failure` would send the result to `postToolUseFailure`, so an original `resultType` other than `success` is kept as a prefix of the text, such as `[failure] `.
- **`userPromptTransformed`** redacts the transformed prompt and returns it as `modifiedTransformedPrompt`. This is experimental.

The redaction is recorded as a `REDACTED` audit entry with counts only. The hook does not restore placeholders.

**Behaviour change.** With redaction on, a secret or personal data in a tool result is now redacted and allowed, where it used to be blocked. With `SENTINEL_HOOK_REDACT=off` it still blocks.

The prompt on `userPromptSubmitted` and the tool arguments on `preToolUse` cannot be rewritten, so a PII or credential finding there uses the action of its severity, and its audit summary ends with `; not redacted`. See [Redaction → Per surface](../redaction#per-surface).

**Placeholder guard.** Because the hook cannot restore a placeholder, writing one into a file or a command would replace the real value. On `preToolUse`, the hook therefore denies a `create`, `edit`, `str_replace_editor`, `apply_patch`, `bash`, `powershell`, `write_bash` or `write_powershell` call whose input contains text of the exact placeholder shape, such as `[EMAIL_1_k3f9x2]`. Ordinary text of that shape is denied too. `SENTINEL_HOOK_REDACT=off` disables the guard.

## Prompt enforcement

A `Block` on `userPromptSubmitted` does not stop the prompt: in Copilot command hooks it shows as a warning and the hook's output is dropped. To enforce on the prompt, wire `user-prompt-transformed` as well. On a `Block` it replaces the prompt the model receives with the withheld text, and with redaction on it redacts the prompt.

`userPromptTransformed` with `modifiedTransformedPrompt` is **experimental** until it is verified with the Copilot CLI. A library caller of `CopilotHookAdapter.HandleAsync` gets the decision only, not the rewritten prompt.

## Diagnostics — did the hook fire?

`SENTINEL_HOOK_VERBOSE=1` produces a stderr line on every invocation:

```
[sentinel-hook] event=user-prompt-submitted decision=Allow session=sess-42
[sentinel-hook] event=user-prompt-submitted decision=Block detector=SEC-01 severity=Critical session=sess-42
```

Use it during initial wiring to confirm the hook actually runs — Copilot's hook integration is newer than Claude Code's and the most common failure mode is "I added the JSON but nothing happens" because of a config-path mismatch.

## Audit destination

Same as the Claude Code adapter: the hook records findings, authorization denials and approval holds to `ai-sentinel/audit.db` under the per-user data folder by default, with `Source` set to `copilot`. Allowed calls are not recorded. The variables are the same three, shared with `sentinel-hook`:

- **SQLite** — `SENTINEL_HOOK_AUDIT_SQLITE=/home/me/.local/share/ai-sentinel/copilot.db` moves the database; `off` disables it
- **NDJSON copy** — `SENTINEL_HOOK_AUDIT_NDJSON=/var/log/ai-sentinel/copilot.ndjson`
- **Size cap** — `SENTINEL_HOOK_AUDIT_MAX_MB` (default `100`, `0` for no cap)
- **Programmatic** — reference `AI.Sentinel.Copilot` library directly

An audit failure never changes a decision, and on Block and Warn it is not printed to stderr unless `SENTINEL_HOOK_VERBOSE` is set; on Allow it is printed with the prefix `[sentinel-copilot-hook] audit:`. See [Claude Code → Audit destination](./claude-code#audit-destination) for the full details, including `sentinel dashboard` to browse the file.

## Native binary (faster cold start)

Same AOT story as Claude Code:

```bash
dotnet publish src/AI.Sentinel.Copilot.Cli -c Release -f net10.0 -r linux-x64 -p:PublishAot=true
# Output: bin/Release/net10.0/linux-x64/publish/sentinel-copilot-hook
```

Point Copilot at the full binary path:

```json
{
  "version": 1,
  "hooks": {
    "userPromptSubmitted": [
      { "type": "command", "bash": "/usr/local/bin/sentinel-copilot-hook user-prompt-submitted", "timeoutSec": 10 }
    ]
  }
}
```

10× faster cold start than the `dotnet tool` entry point. Recommended for repos where Copilot fires hooks on every keystroke or every tool invocation.

## Difference from Claude Code

| Aspect | Claude Code | Copilot |
|---|---|---|
| Config file | `~/.claude/settings.json` (or `.claude/settings.json` per project) | `hooks.json` (per repo) |
| Hook event names | `UserPromptSubmit`, `PreToolUse`, `PostToolUse` (PascalCase) | `userPromptSubmitted`, `preToolUse`, `postToolUse` (camelCase) |
| CLI binary | `sentinel-hook` | `sentinel-copilot-hook` |
| Tool matcher syntax | `"matcher": "*"` per hook entry | `"timeoutSec": 10` per hook entry |
| Block signaling | exit 2 on `UserPromptSubmit` and `PreToolUse`; withheld output on `PostToolUse` | exit 2 on `preToolUse`, advisory on `userPromptSubmitted`; withheld result or prompt on `postToolUse` and `userPromptTransformed` |

The shared env-var contract (`SENTINEL_HOOK_ON_*`) means you configure once and both adapters honor it identically.

## Programmatic use

`AI.Sentinel.Copilot` (the library, not the `.Cli` tool) exposes `CopilotHookAdapter` and the vendor-agnostic `HookPipelineRunner` as public types. Use this when bundling AI.Sentinel inside a custom Copilot-compatible agent.

Redaction is off in a `CopilotHookConfig` you build yourself, including the default one, so `HandleAsync` keeps the 3.0 behaviour: a secret in a tool result gives the severity decision, `Block` by default. `CopilotHookConfig.FromEnvironment` turns it on, as the CLI does, unless `SENTINEL_HOOK_REDACT` is off. To opt in, set `RedactToolResults = true`. On `postToolUse` your host must then deliver `HookOutput.UpdatedToolOutput` instead of the original result: the redacted result on `Allow`, or on `Block` the withheld text as a JSON string. `HandleAsync` scans a `userPromptTransformed` prompt without redacting it, because it cannot return a rewritten prompt.

The decision follows the action your `SentinelOptions` give each detection: `Quarantine` maps through the hook config by severity, `Alert` surfaces as `Warn`, or as `Allow` when the config maps that severity to `Allow`, and `Log` gives `Allow`. The hook answers the most restrictive of these per-detection decisions, so a compliance `Warn` is kept when a `Low` finding mapped to `Allow` fires alongside it; the reason names the detection behind the decision, the higher severity on a tie. With a stock `AddAISentinel()`, a `High` finding is an `Alert` and so a `Warn`; the `sentinel-copilot-hook` CLI sets every severity to `Quarantine` so that `SENTINEL_HOOK_ON_*` decides.

## Next: [MCP proxy](./mcp-proxy) — covers Cursor, Continue, Cline, Windsurf, and Copilot's MCP path
