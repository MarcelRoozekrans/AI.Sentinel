---
sidebar_position: 1
title: Installation
---

# Installation

## Requirements

- **.NET 8** or **.NET 9** target framework
- **`Microsoft.Extensions.AI`** ≥ 9.x (the `IChatClient` abstraction)

That's it. No native dependencies, no out-of-process services, no databases unless you opt into the SQLite audit store.

## Core install

The minimum viable install — gets you the pipeline, all 55 detectors, the intervention engine, and the in-memory ring-buffer audit store:

```bash
dotnet add package AI.Sentinel
```

## Optional packages

Pick what you need; everything is independently versioned and additive.

### Dashboard

```bash
dotnet add package AI.Sentinel.AspNetCore
```

Embedded real-time dashboard. No JS framework — HTMX + Server-Sent Events. Mount with `app.UseAISentinel("/route-prefix")`.

### Persistent audit

```bash
dotnet add package AI.Sentinel.Sqlite
```

`SqliteAuditStore` — single-file SQLite database. Hash-chain integrity preserved across process restarts. Time-based retention sweep.

### Audit forwarders to external SIEMs

```bash
dotnet add package AI.Sentinel.AzureSentinel    # Azure Monitor Logs Ingestion API
dotnet add package AI.Sentinel.OpenTelemetry    # OTel collector (vendor-neutral)
```

NDJSON file forwarder is in the core package — no separate install.

### Custom detector SDK

```bash
dotnet add package AI.Sentinel.Detectors.Sdk
```

`SentinelContextBuilder`, `FakeEmbeddingGenerator`, `DetectorTestBuilder`. You only need this package if you're *writing* custom detectors — `IDetector` itself lives in `AI.Sentinel`.

### CLI tools (`dotnet tool install`)

```bash
dotnet tool install -g AI.Sentinel.Cli              # offline replay for forensics + CI
dotnet tool install -g AI.Sentinel.Mcp.Cli          # stdio MCP proxy
dotnet tool install -g AI.Sentinel.ClaudeCode.Cli   # Claude Code hook adapter
dotnet tool install -g AI.Sentinel.Copilot.Cli      # GitHub Copilot hook adapter
```

## TFM matrix

| Package | net8.0 | net9.0 |
|---|:---:|:---:|
| `AI.Sentinel` | ✓ | ✓ |
| `AI.Sentinel.AspNetCore` | ✓ | ✓ |
| `AI.Sentinel.Detectors.Sdk` | ✓ | ✓ |
| `AI.Sentinel.Sqlite` | ✓ | ✓ |
| `AI.Sentinel.AzureSentinel` | ✓ | ✓ |
| `AI.Sentinel.OpenTelemetry` | ✓ | ✓ |
| `AI.Sentinel.Mcp` | ✓ | ✓ |
| `AI.Sentinel.ClaudeCode` | ✓ | ✓ |
| `AI.Sentinel.Copilot` | ✓ | ✓ |
| CLIs (`*.Cli`) | ✓ | — (single-TFM tool) |

CLIs ship as `dotnet tool` packages targeting net8.0 specifically. Library packages multi-target so you can drop them into either an net8 or net9 host.

## What you get out of the box

Once `AI.Sentinel` is installed and `AddAISentinel()` is called, these services are wired into DI as singletons:

- `IDetectionPipeline` — runs the 55 detectors in parallel per call
- `InterventionEngine` — applies the configured `OnCritical`/`OnHigh`/`OnMedium`/`OnLow` action
- `IAuditStore` — `RingBufferAuditStore` (in-memory, bounded by `opts.AuditCapacity`, default 10,000)
- `IAlertSink` — `NullAlertSink` unless `opts.AlertWebhook` is set
- `IToolCallGuard` — `DefaultToolCallGuard` (allow-by-default unless you wire policies)

55 official detectors auto-register via the `[Singleton(As = typeof(IDetector))]` source generator — no manual `AddTransient<IDetector, ...>()` calls.

## Next: [Quick start](./quick-start) — wire it into your chat client in 5 minutes
