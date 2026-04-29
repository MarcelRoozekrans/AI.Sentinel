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

What each action does:

- **`Block`** → hook exits with code 2. Claude Code surfaces "call blocked" + the detector ID and reason on stderr.
- **`Warn`** → exit 0 with the reason on stderr (visible in Claude Code's log).
- **`Allow`** → silent pass.

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

## Diagnostics — did the hook fire?

`SENTINEL_HOOK_VERBOSE=1` produces a stderr line on every invocation, including `Allow` outcomes:

```
[sentinel-hook] event=user-prompt-submit decision=Allow session=sess-42
[sentinel-hook] event=user-prompt-submit decision=Block detector=SEC-01 severity=Critical session=sess-42
```

Useful when wiring the hook for the first time ("did it actually run?") or when a block was expected but didn't happen. Leave off in steady state — Block/Warn already emit their own reason to stderr.

## Audit destination

By default, the hook runs in-process and uses an ephemeral `RingBufferAuditStore` — audit entries are lost when the hook exits. Three options for persistence:

### NDJSON file

Set the audit path via env var; the hook will append to it across invocations:

```bash
export SENTINEL_HOOK_AUDIT_NDJSON=/var/log/ai-sentinel/claude-code.ndjson
```

One line per audit entry; ship via Filebeat/Vector. See [NDJSON file forwarder](../audit-forwarders/ndjson) for shipping recipes.

### SQLite

```bash
export SENTINEL_HOOK_AUDIT_SQLITE=/home/me/.local/share/ai-sentinel/claude-code.db
```

Single-file persistent store. Hash chain across invocations. Useful for forensic spot-checks via the (planned) `AI.Sentinel.Cli` query commands.

### Programmatic

For custom audit destinations or richer integration, reference the `AI.Sentinel.ClaudeCode` library directly in a C# host:

```csharp
using AI.Sentinel.ClaudeCode;
var adapter = new HookAdapter(/* configure DI for AI.Sentinel + custom IAuditStore */);
await adapter.RunAsync(stdin: Console.OpenStandardInput(), stdout: Console.OpenStandardOutput());
```

Useful when you want a hook that ships entries to your own backend (Splunk, custom REST API, etc.) without going through file forwarders.

## Native binary (faster cold start)

The hook CLI is Native-AOT ready. A native single-file binary cuts cold-start latency by roughly 10× compared to the `dotnet tool` entry point — worth it if hooks fire on every tool call.

```bash
dotnet publish src/AI.Sentinel.ClaudeCode.Cli -c Release -r linux-x64 -p:PublishAot=true
# Output: bin/Release/net8.0/linux-x64/publish/sentinel-hook
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
- **Credential leaks in tool results** (`SEC-02`) — blocked. A tool returned a file containing API keys; PostToolUse blocks the result before Claude Code processes it.
- **PII in either direction** (`SEC-23`) — depends on severity. SSN/credit card → Block; phone numbers → Warn (default `OnMedium=Warn`).
- **Borderline jailbreaks** (`SEC-05`) — depends on cosine similarity. Exact-phrase matches block; loose paraphrases warn.
- **Repetitive output** (`OPS-02`) — the default `OnMedium=Warn` lets these pass with a stderr note.

Tune via env vars to match your risk appetite.

## Programmatic use

The underlying library `AI.Sentinel.ClaudeCode` exposes `HookAdapter` and the vendor-agnostic `HookPipelineRunner` as public types. Reference the library package (not the `.Cli` tool package) to write your own host integration in C# — useful when you want to bundle AI.Sentinel inside a different agent framework or custom CLI.

## Next: [GitHub Copilot](./copilot) — same shape, different config file
