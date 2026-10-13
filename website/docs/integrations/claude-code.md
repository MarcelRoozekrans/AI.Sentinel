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
| `SENTINEL_EMBEDDING_ENDPOINT` | — | Full embeddings URL, e.g. `https://api.openai.com/v1/embeddings` or `http://localhost:11434/v1/embeddings`. Enables semantic detection |
| `SENTINEL_EMBEDDING_MODEL` | — | Model identifier, e.g. `text-embedding-3-small` or `nomic-embed-text` |
| `SENTINEL_EMBEDDING_API_KEY` | — | Bearer token. Omit for local servers that need none |
| `SENTINEL_EMBEDDING_DIMENSIONS` | — | Vector length, when the model allows a choice |
| `SENTINEL_EMBEDDING_CACHE_DIR` | per-user cache dir | Where reference vectors are cached. Must not be world-writable — see below |

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

**Size cap.** The cap is enforced when the hook opens the file: the oldest entries are deleted until the file is under the cap. The hook never runs `VACUUM`, because that would hold the write lock for a long time, so the file stops growing at about the cap instead of shrinking.

**Failures never change a decision.** If the audit file cannot be opened or written, the hook still allows, warns or blocks exactly as it would have. On `Block` and `Warn` the audit problem is not printed to stderr, because stderr carries the reason Claude Code feeds back to the model, unless `SENTINEL_HOOK_VERBOSE` is set. On `Allow` it is printed with the prefix `[sentinel-hook] audit:`.

### NDJSON copy

```bash
export SENTINEL_HOOK_AUDIT_NDJSON=/var/log/ai-sentinel/claude-code.ndjson
```

One line per audit entry; ship via Filebeat/Vector. See [NDJSON file forwarder](../audit-forwarders/ndjson) for shipping recipes. The NDJSON file does not support several processes writing to the same file on Windows (see [#349](https://github.com/MarcelRoozekrans/AI.Sentinel/issues/349)), so give each tool its own path there.

### Browse the audit file

```bash
dotnet tool install -g AI.Sentinel.Cli
sentinel dashboard
```

`sentinel dashboard [--db <path>] [--port <port>]` serves the dashboard over the audit file at `http://127.0.0.1:5170/ai-sentinel/` by default. It listens on loopback only and does not open a browser. On start it prints `Audit chain intact: N entries` or `Audit chain broken at entry {id}`. It refuses a file that does not exist, never appends to the file and shows no approvals panel. It needs the ASP.NET Core runtime, which the .NET SDK includes. The dashboard has a Source column and a `source` filter, so you can separate Claude Code, Copilot and MCP entries.

### Programmatic

For custom audit destinations or richer integration, reference the `AI.Sentinel.ClaudeCode` library directly in a C# host. Register AI.Sentinel and your own `IAuditStore` in DI, then hand the provider to `HookAdapter`:

```csharp
using AI.Sentinel.ClaudeCode;

var adapter = new HookAdapter(provider, HookConfig.FromEnvironment(env));
var input = new HookInput(
    SessionId: "sess-42", Prompt: "hello", ToolName: null, ToolInput: null, ToolResponse: null);
HookOutput output = await adapter.HandleAsync(HookEvent.UserPromptSubmit, input, ct);
// output.Decision is Allow, Warn or Block; output.Reason explains a Warn or Block.
```

`provider` is an `IServiceProvider`, `env` an `IReadOnlyDictionary<string, string?>` and `ct` a `CancellationToken`. `HookConfig` is optional; without it the defaults apply.

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
