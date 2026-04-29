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
    "preToolUse": [
      { "type": "command", "bash": "sentinel-copilot-hook pre-tool-use", "timeoutSec": 10 }
    ],
    "postToolUse": [
      { "type": "command", "bash": "sentinel-copilot-hook post-tool-use", "timeoutSec": 10 }
    ]
  }
}
```

Three hook points:

| Hook | When it fires | What gets scanned |
|---|---|---|
| `userPromptSubmitted` | Every user message | The prompt text |
| `preToolUse` | Before any tool call | Tool name + arguments |
| `postToolUse` | After every tool call | Tool result text |

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

What each action does:

- **`Block`** → hook exits 2. Copilot surfaces the call as blocked with the detector ID and reason on stderr.
- **`Warn`** → exit 0 with the reason on stderr (visible in Copilot's log).
- **`Allow`** → silent pass.

## Diagnostics — did the hook fire?

`SENTINEL_HOOK_VERBOSE=1` produces a stderr line on every invocation:

```
[sentinel-hook] event=user-prompt-submitted decision=Allow session=sess-42
[sentinel-hook] event=user-prompt-submitted decision=Block detector=SEC-01 severity=Critical session=sess-42
```

Use it during initial wiring to confirm the hook actually runs — Copilot's hook integration is newer than Claude Code's and the most common failure mode is "I added the JSON but nothing happens" because of a config-path mismatch.

## Audit destination

Same options as the Claude Code adapter:

- **NDJSON file** — `SENTINEL_HOOK_AUDIT_NDJSON=/var/log/ai-sentinel/copilot.ndjson`
- **SQLite** — `SENTINEL_HOOK_AUDIT_SQLITE=/home/me/.local/share/ai-sentinel/copilot.db`
- **Programmatic** — reference `AI.Sentinel.Copilot` library directly

See [Claude Code → Audit destination](./claude-code#audit-destination) for the full matrix and shipping recipes — the env vars and file formats are identical.

## Native binary (faster cold start)

Same AOT story as Claude Code:

```bash
dotnet publish src/AI.Sentinel.Copilot.Cli -c Release -r linux-x64 -p:PublishAot=true
# Output: bin/Release/net8.0/linux-x64/publish/sentinel-copilot-hook
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
| Block signaling | exit code 2 | exit code 2 |

The shared env-var contract (`SENTINEL_HOOK_ON_*`) means you configure once and both adapters honor it identically.

## Programmatic use

`AI.Sentinel.Copilot` (the library, not the `.Cli` tool) exposes `CopilotHookAdapter` and the vendor-agnostic `HookPipelineRunner` as public types. Use this when bundling AI.Sentinel inside a custom Copilot-compatible agent.

## Next: [MCP proxy](./mcp-proxy) — covers Cursor, Continue, Cline, Windsurf, and Copilot's MCP path
