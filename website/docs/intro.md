---
sidebar_position: 1
title: Introduction
---

# Introduction

**AI.Sentinel** is security monitoring middleware for `IChatClient` ([Microsoft.Extensions.AI](https://learn.microsoft.com/en-us/dotnet/ai/microsoft-extensions-ai)). It wraps any LLM client transparently, scans every prompt and response through 51 detectors, and blocks, alerts, or logs threats — with an embedded real-time dashboard.

## The problem

When you connect an LLM to your application you inherit a new attack surface. Users can craft messages that override the model's instructions (**prompt injection**), the model can leak credentials or PII it saw in context (**credential exposure**), or return fabricated citations and wildly inconsistent numbers (**hallucination**). None of these are bugs in your code — they happen at the model boundary, which your existing middleware stack doesn't see.

AI.Sentinel sits at that boundary:

```
User prompt → [AI.Sentinel: scan] → LLM → [AI.Sentinel: scan] → Your app
```

It scans both directions on every call. If something looks wrong it can quarantine the message before it reaches the model, or quarantine the response before it reaches the user. If it only looks suspicious it alerts your logging/event system. Everything is stored in an in-process audit ring buffer and surfaced on a live dashboard.

## Packages

AI.Sentinel ships as 13 focused NuGet packages so you only take dependencies you need:

| Package | Purpose |
|---|---|
| `AI.Sentinel` | Core — pipeline, 51 detectors, intervention engine, audit store |
| `AI.Sentinel.Detectors.Sdk` | SDK for writing and testing custom detectors — `SentinelContextBuilder`, `FakeEmbeddingGenerator`, `DetectorTestBuilder` |
| `AI.Sentinel.AspNetCore` | Embedded dashboard (no JS framework, HTMX + SSE) |
| `AI.Sentinel.Cli` | `dotnet tool install AI.Sentinel.Cli` — offline replay CLI for forensics + CI |
| `AI.Sentinel.Sqlite` | Persistent `SqliteAuditStore` with hash-chain integrity |
| `AI.Sentinel.AzureSentinel` | `AzureSentinelAuditForwarder` to Azure Monitor Logs Ingestion API |
| `AI.Sentinel.OpenTelemetry` | `OpenTelemetryAuditForwarder` — vendor-neutral via OTel collector |
| `AI.Sentinel.Mcp` / `.Mcp.Cli` | Stdio MCP proxy that scans `tools/call` + `prompts/get` for any MCP-speaking host |
| `AI.Sentinel.ClaudeCode` / `.ClaudeCode.Cli` | Native hook adapter for Claude Code's `settings.json` hooks |
| `AI.Sentinel.Copilot` / `.Copilot.Cli` | Native hook adapter for GitHub Copilot's `hooks.json` |

## What's next

- **[Installation](./getting-started/installation)** — `dotnet add package AI.Sentinel`
- **[Quick start](./getting-started/quick-start)** — `services.AddAISentinel(opts => ...)` + `.UseAISentinel()`
- **[Architecture](./core-concepts/architecture)** — how prompt and response scans flow through the pipeline
- **[Detector reference](./detectors/overview)** — what the 51 built-in detectors look for
- **[Custom detectors](./custom-detectors/sdk-overview)** — write and unit-test your own
