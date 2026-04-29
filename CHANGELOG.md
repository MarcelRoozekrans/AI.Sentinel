# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Subsequent entries are generated automatically by
[release-please](https://github.com/googleapis/release-please) from
[Conventional Commits](https://www.conventionalcommits.org/).

## [Unreleased]

### Highlights

- **Per-pipeline configuration (Phase A).** `services.AddAISentinel("name", opts => ...)` and `.UseAISentinel("name")` register multiple isolated pipelines under string names. Audit infrastructure stays shared; per-name detector tuning rides on `Configure<T>`.
- **Fluent per-detector config.** `opts.Configure<T>(c => ...)` disables a detector or clamps its severity output (Floor/Cap). Pipeline-level concern, no detector code changes.
- **`AI.Sentinel.Detectors.Sdk` v1.1 — `DetectorTestBuilder`.** Fluent assertion helper for unit-testing custom detectors: `WithDetector<T>().WithPrompt(...).ExpectDetection(Severity.High)`.
- **`AI.Sentinel.Detectors.Sdk` v1.0 — primitives.** `SentinelContextBuilder` + `FakeEmbeddingGenerator` for testing custom detectors offline.
- **MCP proxy (`AI.Sentinel.Mcp` + `AI.Sentinel.Mcp.Cli`).** Stdio MCP proxy that scans `tools/call` and `prompts/get` for any MCP-speaking host (Cursor, Continue, Cline, Windsurf, Copilot).
- **Audit forwarders.** `NdjsonFileAuditForwarder`, `AzureSentinelAuditForwarder`, `OpenTelemetryAuditForwarder` ship in their respective packages, with `BufferingAuditForwarder` for backpressure control.
- **Persistent audit store.** `AI.Sentinel.Sqlite` adds `SqliteAuditStore` with hash-chain integrity and time-based retention.
- **Native hook adapters.** `AI.Sentinel.ClaudeCode` and `AI.Sentinel.Copilot` (with their `.Cli` companions) wire into Claude Code's `settings.json` hooks and GitHub Copilot's `hooks.json` to scan UserPromptSubmit, PreToolUse, PostToolUse.
- **Custom detector support.** `opts.AddDetector<T>()` registers third-party detectors alongside the 51 built-in ones.

This is the pre-1.0 development history. Future entries are generated per release.

## [0.1.0] - Initial development

Initial pre-release. See git history (`git log v0.1.0..HEAD`) for the full set of commits.
