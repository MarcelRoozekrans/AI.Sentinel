---
sidebar_position: 1
title: Claude Code
---

# Claude Code integration

`AI.Sentinel.ClaudeCode.Cli` is a native hook adapter for Anthropic's Claude Code CLI. It runs the AI.Sentinel detector pipeline against every prompt, tool call, and tool result without modifying your application — Claude Code invokes the hook via stdin/stdout per the [Claude Code hooks spec](https://docs.claude.com/en/docs/claude-code/hooks).

## Install

```bash
dotnet tool install -g AI.Sentinel.ClaudeCode.Cli
```

The CLI installs as `sentinel-hook` on your `PATH`. It's a self-contained `dotnet tool` — no runtime configuration in your project.

## Wire it into Claude Code

Edit `~/.claude/settings.json` (user-level) or `.claude/settings.json` (project-level):

```json
{
  "hooks": {
    "UserPromptSubmit": [
      { "hooks": [{ "type": "command", "command": "sentinel-hook user-prompt-submit" }] }
    ],
    "PreToolUse": [
      { "matcher": "*", "hooks": [{ "type": "command", "command": "sentinel-hook pre-tool-use" }] }
    ],
    "PostToolUse": [
      { "matcher": "*", "hooks": [{ "type": "command", "command": "sentinel-hook post-tool-use" }] }
    ]
  }
}
```

Three hook points:

| Hook | When it fires | What gets scanned |
|---|---|---|
| `UserPromptSubmit` | Every user message | The prompt text |
| `PreToolUse` | Before any tool call | Tool name + arguments |
| `PostToolUse` | After every tool call | Tool result text |

Restart Claude Code to pick up the new settings (or re-source the workspace).

## Severity → action

Both Claude Code and Copilot share the same env-var contract:

| Variable | Default | Values |
|---|---|---|
| `SENTINEL_HOOK_ON_CRITICAL` | `Block` | `Block` / `Warn` / `Allow` |
| `SENTINEL_HOOK_ON_HIGH` | `Block` | `Block` / `Warn` / `Allow` |
| `SENTINEL_HOOK_ON_MEDIUM` | `Warn` | `Block` / `Warn` / `Allow` |
| `SENTINEL_HOOK_ON_LOW` | `Allow` | `Block` / `Warn` / `Allow` |
| `SENTINEL_HOOK_VERBOSE` | `false` | `1` / `true` / `yes` → grep-friendly stderr diagnostic |
| `SENTINEL_HOOK_SUPPRESS_SEMANTIC_WARNING` | `false` | `1` / `true` / `yes` → suppress the startup warning that semantic detection is inert. Set only after accepting that SEC-01 and SEC-05 will not fire |
| `SENTINEL_HOOK_REDACT` | `on` | `off` / `0` / `false` / `no` → turn off [redaction](#redaction) of tool output and the placeholder guard. Anything else, or unset, keeps them on |
| `SENTINEL_HOOK_COMPLIANCE` | `off` | `on` / `1` / `true` / `yes` → run the four Art. 5 [compliance detectors](../detectors/compliance), which are off by default. Their findings warn instead of following `SENTINEL_HOOK_ON_HIGH`. Needs `SENTINEL_EMBEDDING_ENDPOINT`. Thresholds are code-only |
| `SENTINEL_HOOK_DETECTORS` | `security` | `security` → the [security preset](./mcp-proxy#detector-profiles) the MCP proxy uses: 16 security detectors plus the four Art. 5 compliance detectors, which run only with `SENTINEL_HOOK_COMPLIANCE=on`. `all` → every detector, including the operational and hallucination detectors that judge a model's reply and fire on tool output, see [Detectors](#detectors). Anything else, or unset, keeps `security` |
| `SENTINEL_EMBEDDING_ENDPOINT` | — | Full embeddings URL, e.g. `https://api.openai.com/v1/embeddings` or `http://localhost:11434/v1/embeddings`. Enables semantic detection |
| `SENTINEL_EMBEDDING_MODEL` | — | Model identifier, e.g. `text-embedding-3-small` or `nomic-embed-text` |
| `SENTINEL_EMBEDDING_API_KEY` | — | Bearer token. Omit for local servers that need none |
| `SENTINEL_EMBEDDING_DIMENSIONS` | — | Vector length, when the model allows a choice |
| `SENTINEL_EMBEDDING_CACHE_DIR` | per-user cache dir | Where reference vectors are cached. Must not be world-writable — see below |

### Detectors

The hook scans prompts, tool arguments and tool output, never a model's reply. So by default it runs the same security preset as the [MCP proxy](./mcp-proxy#detector-profiles): 16 of the 32 security detectors and the four compliance detectors. It leaves out the operational and hallucination detectors, which were written for a model's reply and fire as noise on tool traffic. Build logs and directory listings repeat lines, so `OPS-02` flags them. `OPS-11` rates a tool output more than 100 times the size of the tool call, or above 50,000 characters, as `High`, which blocks under the default `SENTINEL_HOOK_ON_HIGH=Block`. `SENTINEL_HOOK_DETECTORS=all` runs every detector.

**Behaviour change.** Until this preset, the hooks ran every detector. The default now also leaves out the 16 security detectors that are not in the preset, including the rule-based `SEC-32` SystemPromptEcho, which fires without an embedding endpoint. A hook that relied on any detector outside the preset needs `SENTINEL_HOOK_DETECTORS=all`.

### What each action does

The hook writes the output the [Claude Code hooks spec](https://docs.claude.com/en/docs/claude-code/hooks) documents:

- **`Block` on `UserPromptSubmit` or `PreToolUse`** → the hook exits 2 with the reason on stderr and writes nothing to stdout. Claude Code stops the prompt or the tool call and shows the reason.
- **`Block` on `PostToolUse`** → the tool has already run, so the hook exits 0 and withholds its output. stdout carries `"decision": "block"`, the reason, and an `updatedToolOutput` in place of the tool's output. See [Withheld output](#withheld-output).
- **`Warn`** → exit 0 with `{"systemMessage": "AI.Sentinel: <reason>"}` on stdout. Claude Code shows the message to the user.
- **`Allow`** → exit 0 with `{}` on stdout.

### Redaction

With `SENTINEL_HOOK_REDACT` on, the default, `PostToolUse` redacts personal data and secrets in the tool output. The hook returns the redacted output as `updatedToolOutput`, so the model sees `[EMAIL_1_k3f9x2]` in place of the address, together with an `additionalContext` note such as:

```text
AI.Sentinel redacted 1 EMAIL in this tool output. Placeholders such as [EMAIL_n_tag] stand for the real values; do not write them to files or commands.
```

The redaction is recorded as a `REDACTED` audit entry with counts only. The hook does not restore placeholders: the model keeps them for the rest of the session.

Not everything can be redacted. A command hook cannot rewrite the prompt on `UserPromptSubmit` or the tool arguments on `PreToolUse`, so a PII or credential finding there uses the action of its severity, and its audit summary ends with `; not redacted`. See [Redaction → Per surface](../redaction#per-surface).

**Placeholder guard.** Because the hook cannot restore a placeholder, writing one into a file or a command would replace the real value. On `PreToolUse`, the hook therefore denies a `Write`, `Edit`, `MultiEdit`, `NotebookEdit` or `Bash` call whose input contains text of the exact placeholder shape, such as `[EMAIL_1_k3f9x2]`, with exit 2 and a fixed reason that asks the model to get the value from the user. Ordinary text of that shape is denied too. `SENTINEL_HOOK_REDACT=off` disables the guard.

**When a tool rejects the output.** Claude Code checks `updatedToolOutput` against the tool's own output shape. Live checks with Claude Code 2.1.296 showed that `Read` accepts the redacted output, and that `Read` and `Bash` accept the withheld output. A built-in tool that rejects it has its original output shown to the model. The `additionalContext` note, which names the redacted types or the block reason, is then the only mitigation, and it does not hide the value.

### Withheld output

When a `PostToolUse` scan blocks, the output is withheld, also with `SENTINEL_HOOK_REDACT=off`. The withheld output keeps the shape of the tool's `tool_response`, because Claude Code rejects an output of another shape and then shows the original:

- identifier-like `type` values, such as `"type": "text"`, are kept;
- empty strings stay empty;
- numbers, booleans, nulls and property names are kept;
- every other string becomes `withheld by AI.Sentinel: <reason>`.

A first version also replaced `"type": "text"`. Claude Code rejected it and showed the original `Read` output, which is why `type` values are kept.

Set the env vars in your shell profile or directly in `settings.json`:

```json
{
  "env": {
    "SENTINEL_HOOK_ON_HIGH": "Block",
    "SENTINEL_HOOK_ON_MEDIUM": "Warn",
    "SENTINEL_HOOK_VERBOSE": "1"
  },
  "hooks": { /* ... */ }
}
```

## When the hook itself fails

The hook fails closed on `PreToolUse`. When it cannot evaluate a tool call, it blocks the call with exit 2 and a reason that starts with `Sentinel internal error:` on stderr. This covers:

- a `SENTINEL_APPROVAL_CONFIG` that cannot be loaded or fails validation: `Sentinel internal error: approval config '<path>' could not be loaded: <message>`. Without this, one typo in the file would turn off every approval rule;
- an unexpected exception in the hook, for example an approval database that cannot be opened: `Sentinel internal error: <ExceptionType>: <message>`;
- input without a `tool_name`, while `SENTINEL_APPROVAL_CONFIG` has approval rules: `Sentinel internal error: PreToolUse input has no tool name`. Such a call cannot be checked against the rules. Without approval rules it is scanned and allowed as before;
- stdin that is empty or not valid JSON: `Sentinel internal error: malformed stdin JSON: <message>`, or `Sentinel internal error: empty stdin JSON: <message>` when stdin is the JSON `null`.

Tool calls stay blocked for as long as the cause persists. Fix the config file, or unset `SENTINEL_APPROVAL_CONFIG` to run without approval rules. The block is recorded in the [audit file](#audit-destination) as an `AUTHZ-DENY` entry with the code `internal_error` and the policy name `sentinel-internal`; when the input names no tool, the entry has the tool `unknown`, and for unreadable stdin also a new session id. If the hook times out or is killed, Claude Code does not treat that as a block: that behaviour belongs to Claude Code, not to Sentinel.

On `UserPromptSubmit` and `PostToolUse` the same failures exit 1 with the error on stderr. Claude Code shows it and goes on: exit 1 is not a block. A detector that fails, for example because the embedding endpoint is down, does not block on any event: it is skipped for that scan, reported on stderr, and the other detectors still run.

## Diagnostics — did the hook fire?

`SENTINEL_HOOK_VERBOSE=1` produces a stderr line on every invocation, including `Allow` outcomes:

```
[sentinel-hook] event=user-prompt-submit decision=Allow session=sess-42
[sentinel-hook] event=user-prompt-submit decision=Block detector=SEC-01 severity=Critical session=sess-42
```

Useful when wiring the hook for the first time ("did it actually run?") or when a block was expected but didn't happen. Leave off in steady state — Block and Warn already report their reason.

## Audit destination

The hook records to a local SQLite file by default, with no configuration. Every entry goes to `ai-sentinel/audit.db` under the per-user data folder: `~/.local/share` on Linux, `~/Library/Application Support` on macOS and `%LOCALAPPDATA%` on Windows.

- **What is recorded:** findings, authorization denials and approval holds. Allowed calls are not recorded.
- **Where it is shared:** the Copilot hook and the MCP proxy write to the same file, so one database holds everything your agents did. Several processes can write to it at once. Each entry's `Source` says which tool wrote it: `claude-code`, `copilot` or `mcp`.
- **Session id:** hook entries carry the session id Claude Code passes to the hook.
- **Permissions:** on Linux and macOS the directory is created `0700` and the files `0600`.
- **No data folder:** if the machine has no per-user data folder (for instance `HOME` is unset), recording is off and the hook reports a problem. Set `SENTINEL_HOOK_AUDIT_SQLITE` to a path to record anyway.
- **Chain:** the entries form a SHA-256 hash chain that continues across invocations. Browse and verify the file with [`sentinel dashboard`](#browse-the-audit-file).

| Variable | Default | Values |
|---|---|---|
| `SENTINEL_HOOK_AUDIT_SQLITE` | `<data folder>/ai-sentinel/audit.db` | A database path, or `off` (any case) to use the in-memory ring buffer and lose entries when the hook exits |
| `SENTINEL_HOOK_AUDIT_NDJSON` | — | A file path. Adds an NDJSON copy of every entry, next to the database |
| `SENTINEL_HOOK_AUDIT_MAX_MB` | `100` | Size cap in megabytes. `0` means no cap |

**Size cap.** The cap is enforced when the hook opens the file. Usage is measured in pages in use (pages minus free pages, times page size), not in file length, so it drops as soon as rows are deleted. The oldest entries are deleted in batches of 10% of the rows, at least 100, and one trim stops after at most 8 batches. A file far over the cap can therefore need more than one open to come under it. The hook never runs `VACUUM`, because that would hold the write lock for a long time, so the file stops growing at about the cap instead of shrinking.

**Failures never change a decision.** If the audit file cannot be opened or written, the hook still allows, warns or blocks exactly as it would have. On a `Block` that exits 2 the audit problem is not printed to stderr, because stderr carries the reason Claude Code feeds back to the model, unless `SENTINEL_HOOK_VERBOSE` is set. Otherwise it is printed with the prefix `[sentinel-hook] audit:`.

### NDJSON copy

```bash
export SENTINEL_HOOK_AUDIT_NDJSON=/var/log/ai-sentinel/claude-code.ndjson
```

One line per audit entry; ship via Filebeat/Vector. See [NDJSON file forwarder](../audit-forwarders/ndjson) for shipping recipes. Several hook processes, and the Copilot hook and MCP proxy, can share one NDJSON path: appends are serialised through a lock file, so no line is lost or interleaved.

### Browse the audit file

```bash
dotnet tool install -g AI.Sentinel.Cli
sentinel dashboard
```

`sentinel dashboard [--db <path>] [--port <port>]` serves the dashboard over the audit file at `http://127.0.0.1:5170/ai-sentinel/` by default. It listens on loopback only and does not open a browser. On start it prints `Audit chain intact: N entries` or `Audit chain broken at entry {id}`. It refuses a file that does not exist and shows no approvals panel. It opens the file read-only: it never creates the file, never upgrades an older schema (run a hook or the MCP proxy once to upgrade it), and never appends. SQLite may create `-wal` and `-shm` files next to it. It needs the ASP.NET Core runtime, which the .NET SDK includes. The dashboard has a Source column and a `source` filter, so you can separate Claude Code, Copilot and MCP entries.

### Programmatic

For custom audit destinations or richer integration, reference the `AI.Sentinel.ClaudeCode` library directly in a C# host. Register AI.Sentinel and your own `IAuditStore` in DI, then hand the provider to `HookAdapter`:

```csharp
using AI.Sentinel.ClaudeCode;

var adapter = new HookAdapter(provider, HookConfig.FromEnvironment(env));
var input = new HookInput { SessionId = "sess-42", Prompt = "hello" };
HookOutput output = await adapter.HandleAsync(HookEvent.UserPromptSubmit, input, ct);
// output.Decision is Allow, Warn or Block; output.Reason explains a Warn or Block.
```

`provider` is an `IServiceProvider`, `env` an `IReadOnlyDictionary<string, string?>` and `ct` a `CancellationToken`. `HookConfig` is optional; without it the defaults apply.

Redaction is off in a `HookConfig` you build yourself, including the default one, so `PostToolUse` keeps the 3.0 behaviour: a secret in the tool output gives the severity decision, `Block` by default. `HookConfig.FromEnvironment`, as in the example, turns it on, as the CLI does, unless `SENTINEL_HOOK_REDACT` is off. To opt in on a config of your own, set `RedactToolResults = true`. On `PostToolUse` your host must then deliver `HookOutput.UpdatedToolOutput` instead of the original output: the redacted output on `Allow`, or on `Block` the withheld body that keeps the output's shape.

The decision follows the action your `SentinelOptions` give each detection: `Quarantine` maps through `HookConfig` by severity, `Alert` surfaces as `Warn`, or as `Allow` when `HookConfig` maps that severity to `Allow`, and `Log` gives `Allow`. The hook answers the most restrictive of these per-detection decisions, so a compliance `Warn` is kept when a `Low` finding mapped to `Allow` fires alongside it; the reason names the detection behind the decision, the higher severity on a tie. With a stock `AddAISentinel()`, a `High` finding is an `Alert` and so a `Warn`; the `sentinel-hook` CLI sets every severity to `Quarantine` so that `SENTINEL_HOOK_ON_*` decides.

Useful when you want a hook that ships entries to your own backend (Splunk, custom REST API, etc.) without going through file forwarders.

## Native binary (faster cold start)

The hook CLI is Native-AOT ready. A native single-file binary cuts cold-start latency by roughly 10× compared to the `dotnet tool` entry point — worth it if hooks fire on every tool call.

```bash
dotnet publish src/AI.Sentinel.ClaudeCode.Cli -c Release -f net10.0 -r linux-x64 -p:PublishAot=true
# Output: bin/Release/net10.0/linux-x64/publish/sentinel-hook
```

Replace `linux-x64` with `win-x64`, `osx-arm64`, etc. Point the hook `command` at the binary's full path instead of `sentinel-hook`:

```json
{
  "hooks": {
    "UserPromptSubmit": [
      { "hooks": [{ "type": "command", "command": "/usr/local/bin/sentinel-hook user-prompt-submit" }] }
    ]
  }
}
```

**Prereqs on Windows:** Visual Studio "Desktop development with C++" workload. Linux needs `clang` + `libc` dev packages. macOS needs Xcode CLT.

## What gets blocked, in practice

With `SENTINEL_HOOK_ON_HIGH=Block` and a typical Claude Code workflow:

- **Prompt injection in user messages** (`SEC-01`) — blocked. The user said "ignore previous instructions"; the hook prevents Claude Code from acting on it.
- **Credential leaks and PII in tool results** — redacted. A tool returned a file containing an API key or an email address; PostToolUse replaces each value with a placeholder before Claude Code processes the result. With `SENTINEL_HOOK_REDACT=off` they follow their severity: an API key blocks and the output is withheld.
- **PII and credentials in prompts and tool arguments** — depends on severity, because these cannot be redacted. SSN/credit card → Block; phone numbers → Warn (default `OnMedium=Warn`).
- **Borderline jailbreaks** (`SEC-05`) — depends on cosine similarity. Exact-phrase matches block; loose paraphrases warn.
- **Repetitive or long tool output** — not flagged. The default [security preset](#detectors) leaves out `OPS-02` and `OPS-11`; with `SENTINEL_HOOK_DETECTORS=all`, repeated lines warn and output much larger than the tool call is withheld.

Tune via env vars to match your risk appetite.

## Programmatic use

The underlying library `AI.Sentinel.ClaudeCode` exposes `HookAdapter` and the vendor-agnostic `HookPipelineRunner` as public types. Reference the library package (not the `.Cli` tool package) to write your own host integration in C# — useful when you want to bundle AI.Sentinel inside a different agent framework or custom CLI.

## Next: [GitHub Copilot](./copilot) — same shape, different config file
