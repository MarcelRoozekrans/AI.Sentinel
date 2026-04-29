---
sidebar_position: 2
title: GitHub Copilot
---

# GitHub Copilot integration

`AI.Sentinel.Copilot` + `AI.Sentinel.Copilot.Cli` mirror the Claude Code adapter for GitHub Copilot's `hooks.json`:

```bash
dotnet tool install -g AI.Sentinel.Copilot.Cli
```

```json
{
  "hooks": {
    "userPromptSubmitted": "ai-sentinel-copilot scan-prompt",
    "preToolUse":          "ai-sentinel-copilot scan-tool-use",
    "postToolUse":         "ai-sentinel-copilot scan-tool-result"
  }
}
```

> Full Copilot integration guide — coming soon.
