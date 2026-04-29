---
sidebar_position: 1
title: Claude Code
---

# Claude Code integration

`AI.Sentinel.ClaudeCode` + `AI.Sentinel.ClaudeCode.Cli` wire AI.Sentinel into Claude Code's hooks. Install the CLI and reference it from `~/.claude/settings.json`:

```bash
dotnet tool install -g AI.Sentinel.ClaudeCode.Cli
```

```json
{
  "hooks": {
    "UserPromptSubmit": [{ "type": "command", "command": "ai-sentinel-claude-code scan-prompt" }],
    "PreToolUse":       [{ "type": "command", "command": "ai-sentinel-claude-code scan-tool-use" }],
    "PostToolUse":      [{ "type": "command", "command": "ai-sentinel-claude-code scan-tool-result" }]
  }
}
```

The hook scans every prompt, tool invocation, and tool result through the configured detector pipeline.

> Full Claude Code integration guide — hook semantics, audit destination configuration, AOT single-file binary — coming soon.
