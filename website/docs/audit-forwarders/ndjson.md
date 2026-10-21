---
sidebar_position: 2
title: NDJSON file
---

# NDJSON file forwarder

Append-only NDJSON (newline-delimited JSON) file forwarder. Zero external dependencies — direct `StreamWriter` append. Operators ship the file via Filebeat, Vector, Fluent Bit, or any log shipper. Universal SIEM coverage by way of "the lowest common denominator everyone supports".

Lives in the core `AI.Sentinel` package — no separate install.

## Wire it up

```csharp
services.AddAISentinel(opts => /* ... */);
services.AddSentinelNdjsonFileForwarder(opts =>
{
    opts.FilePath = "/var/log/ai-sentinel/audit.ndjson";
});
```

The directory must exist. The forwarder creates the file at registration time to check that it can write there, then opens it once per batch and closes it again, so it holds no handle between writes.

## File format

One JSON object per line, terminated with `\n` (LF on every platform — by design, so byte-for-byte cross-platform identical output simplifies SIEM ingestion):

```json
{"id":"abc123","timestamp":"2026-04-29T08:30:00.000Z","hash":"sha256...","previousHash":"sha256...","severity":"High","detectorId":"SEC-01","summary":"PromptInjection match: 'ignore all previous instructions'"}
{"id":"def456","timestamp":"2026-04-29T08:30:00.012Z","hash":"sha256...","previousHash":"sha256...","severity":"Medium","detectorId":"SEC-23","summary":"PII match: SSN pattern"}
```

Every entry is a complete `AuditEntry` serialized via the source-gen JSON context — AOT-safe, no reflection, no allocations beyond the line buffer.

## Performance

- Direct file append, no buffering: each batch is one write call
- Opens the file and its lock file per batch, a few tens of µs on a local SSD
- Thread-safe via internal `SemaphoreSlim` — concurrent writes serialize cleanly
- Flushes after every batch (durability over throughput)

The forwarder is **not** wrapped in `BufferingAuditForwarder` — file appends are already fast enough that batching adds latency without meaningful gain.

## Several processes on one file

Several processes, and several forwarders in one process, can append to the same file on Windows, Linux and macOS. The Claude Code and Copilot hooks and the MCP proxy can all point `SENTINEL_HOOK_AUDIT_NDJSON` / `SENTINEL_MCP_AUDIT_NDJSON` at one path.

Each batch is appended under a lock file next to the NDJSON file, `<file>.lock`:

1. The forwarder opens `<file>.lock` exclusively, retrying with a short backoff while another writer holds it.
2. It opens the NDJSON file at its current end, writes the whole batch in one call, flushes and closes it.
3. It closes the lock file, which releases the lock, also when the write fails.

A batch is therefore never interleaved with, or written over, another writer's batch, and every line is a complete JSON object. The operating system releases the lock when a writer process dies, so a crashed process cannot block the others. Leave `<file>.lock` in place; deleting it while a writer holds it breaks the exclusion.

The file is opened with `FileShare.ReadWrite | FileShare.Delete`, so log shippers can read it and rotation can rename or delete it while writers are running.

If a writer cannot take the lock within `LockTimeout` (default 5 seconds), that batch is dropped and reported like any other send failure:

```csharp
services.AddSentinelNdjsonFileForwarder(opts =>
{
    opts.FilePath = "/var/log/ai-sentinel/audit.ndjson";
    opts.LockTimeout = TimeSpan.FromSeconds(10);
});
```

On Linux and macOS the lock is an advisory `flock` that .NET takes for exclusive opens. Every AI.Sentinel writer honours it; a non-.NET process writing to the same file does not, and neither does a .NET process run with `DOTNET_SYSTEM_IO_DISABLEFILELOCKING=1`.

## Failure handling

Per the [forwarder reliability contract](./overview#forwarder-reliability), failures swallow + log + count:

| Failure | What happens |
|---|---|
| Disk full | Exception swallowed, stderr log, `audit.forward.dropped++` |
| File deleted or rotated away | The next batch creates the file again at the configured path |
| Lock file held past `LockTimeout` | Batch dropped, `action=send_error error=TimeoutException` reported |
| Permission denied at startup | Constructor throws — registration fails, app fails fast |

By default a send failure or dropped batch is written to `Console.Error`. Set `OnError` when stderr is reserved for other output, as in a hook process, where stderr carries the reason fed back to the model:

```csharp
services.AddSentinelNdjsonFileForwarder(opts =>
{
    opts.FilePath = "/var/log/ai-sentinel/audit.ndjson";
    opts.OnError = message => myLogger.LogWarning("{Message}", message);
});
```

`OnError` receives one line per failure. The callback must not throw; an exception from it is ignored. The CLIs set it to collect problems instead of printing them.

The "fail at startup" rule for permission denied is intentional. If you can't open the file at registration time, the configuration is broken and you want to know immediately, not at first request.

## Log shipping patterns

The forwarder writes to a local file. Your log shipper picks up from there.

### Filebeat → Elastic

```yaml
# filebeat.yml
filebeat.inputs:
  - type: log
    paths: ["/var/log/ai-sentinel/audit.ndjson"]
    json.keys_under_root: true
    json.add_error_key: true

output.elasticsearch:
  hosts: ["https://es:9200"]
  index: "ai-sentinel-audit-%{+yyyy.MM.dd}"
```

### Vector → Datadog / S3 / anywhere

```toml
# vector.toml
[sources.ai_sentinel]
type = "file"
include = ["/var/log/ai-sentinel/audit.ndjson"]

[transforms.parse]
type = "remap"
inputs = ["ai_sentinel"]
source = '''. = parse_json!(.message)'''

[sinks.datadog]
type = "datadog_logs"
inputs = ["parse"]
default_api_key = "${DD_API_KEY}"
```

### Fluent Bit → AWS CloudWatch

```ini
[INPUT]
    Name        tail
    Path        /var/log/ai-sentinel/audit.ndjson
    Parser      json

[OUTPUT]
    Name        cloudwatch_logs
    Match       *
    region      us-west-2
    log_group_name    ai-sentinel-audit
    log_stream_prefix ai-sentinel-
```

## Rotation

The forwarder doesn't rotate the file itself — that's by design. Use an external mechanism:

- **logrotate** (Linux) — daily/size-based rotation; both `copytruncate` and the default rename-and-create mode work, because the forwarder opens the file per batch
- **Vector / Fluent Bit** — built-in rotation while ingesting
- **Container orchestrator** — Kubernetes' `RotateKubeletServerCertificate` and similar

Native in-process rotation (rotate by size or time window) is on the [backlog](https://github.com/MarcelRoozekrans/AI.Sentinel/blob/main/docs/BACKLOG.md). Today, hand off rotation to your existing log infrastructure.

## When to use this forwarder

Best fit when:

- You already have a log-shipping pipeline (Filebeat / Vector / Fluent Bit) and want AI.Sentinel audit on it
- You want zero new external service dependencies
- You're running in containers where `stdout` log capture won't quite work because audit entries need to stay separate from application logs
- You want belt-and-suspenders alongside another forwarder ("ship to SIEM via OTel, AND keep an NDJSON tail for forensic spot-checks")

When NOT a great fit:

- You don't have a log shipper installed (NDJSON-on-disk-with-no-shipper is just a file accumulating forever)
- You want bidirectional integration with a specific SIEM — use `AzureSentinelAuditForwarder` or `OpenTelemetryAuditForwarder` instead
- The host's filesystem is ephemeral (containers without persistent volumes) — you'll lose entries on restart

## Cross-platform identical output

Lines are terminated with `\n` (LF) on every platform — Windows uses `\r\n` for `Environment.NewLine` but the forwarder explicitly writes LF. This keeps SIEM-side parsers identical across deployment environments and lets you `diff` audit logs between two replicas without false hash differences.

## Next: [SQLite](./sqlite) — persistent local store with retention sweep
