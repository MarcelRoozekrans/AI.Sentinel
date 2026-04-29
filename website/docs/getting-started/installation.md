---
sidebar_position: 1
title: Installation
---

# Installation

```bash
dotnet add package AI.Sentinel
dotnet add package AI.Sentinel.AspNetCore   # optional — embedded dashboard
dotnet add package AI.Sentinel.Sqlite       # optional — persistent audit store
```

Optional packages: `AI.Sentinel.AzureSentinel`, `AI.Sentinel.OpenTelemetry`, `AI.Sentinel.Detectors.Sdk` (for writing custom detectors), `AI.Sentinel.Mcp.Cli` / `AI.Sentinel.ClaudeCode.Cli` / `AI.Sentinel.Copilot.Cli` (CLI tools).

> Detailed prerequisites, supported TFMs (`net8.0` / `net9.0`), and target-framework guidance — coming soon.
