# Audit recording for the hook CLIs and the MCP proxy

Issue: [#344](https://github.com/MarcelRoozekrans/AI.Sentinel/issues/344)
Date: 2026-10-13

## Intent

When the Claude Code hook, the Copilot hook or the MCP proxy blocks a tool call, or flags a threat in a prompt or a tool result, the agent sees the decision and nothing else keeps it. Every hook invocation is a fresh process with an in-memory ring buffer that disappears when the process exits. The MCP proxy builds its own ring buffer outside DI. Nobody can go back later and see what was blocked, flagged or held for approval.

The docs promise otherwise. `website/docs/integrations/claude-code.md` and `copilot.md` document `SENTINEL_HOOK_AUDIT_NDJSON` and `SENTINEL_HOOK_AUDIT_SQLITE`. Git history shows they were written into the docs on 2026-04-29 and never implemented.

The maintainer wants every decision **recorded in a database by default**, so it can be recalled later, and wants to **see it in the dashboard UI**.

## Goals

1. **Record by default.** With no configuration, both hook CLIs and the MCP proxy write every audit entry to one shared local SQLite file. One file means one history across Claude Code, Copilot and MCP. "Every audit entry" means what is recorded today: detector findings, authorization denials and approval holds.
2. **Know which tool wrote it.** Each entry records its source (Claude Code, Copilot or MCP), so the shared history can be told apart.
3. **Bounded by default.** The default file has a size cap, so recording that is on by default cannot grow without limit.
4. **Configurable.** Env vars move the file, switch recording off, or add an NDJSON copy. The documented `SENTINEL_HOOK_AUDIT_SQLITE` and `SENTINEL_HOOK_AUDIT_NDJSON` work as the docs describe.
5. **Safe with several writers.** Hooks fire concurrently, and the long-lived MCP proxy writes at the same time. All of them append to one file, and the hash chain stays one unbroken line.
6. **Viewable.** A new `sentinel dashboard` command in `AI.Sentinel.Cli` serves the existing dashboard on localhost over that file.
7. **Docs match the code**, including the broken programmatic sample in `claude-code.md`.

## Non-goals

- Recording allowed tool calls. Decided by the maintainer: only findings, denials and approval holds are recorded, as today.
- Approving or denying held tool calls from the `sentinel dashboard` command. The dashboard can do this when an `IApprovalStore` is registered, but wiring the CLIs' approval store into this command is a follow-up.
- A terminal listing such as `sentinel audit list`.
- Team-wide or central collection. Forwarding to a SIEM already covers that, and the new NDJSON option makes it reachable from the CLIs.
- An integrity badge in the dashboard UI. The compliance report (#339) is the place for chain verification output.

## Anti-goals

These would make the change a failure even if it technically worked:

- **Recording changes a decision.** If the audit file is locked, read-only, corrupt or on a full disk, the hook must still return the same allow, block or ask decision. Today an exception in the hook CLIs becomes exit code 1, which Claude Code treats as a tool failure and **not** as a block. An audit write that throws on the deny path would therefore turn a block into a non-block. Audit failures are reported on stderr and never change the outcome.
- **Noticeable latency.** The hook runs on every tool call. Opening the store must not add perceptible delay, and no hook may wait out a long SQLite busy timeout.
- **A forked chain.** Concurrent writers must not produce two entries with the same `PreviousHash`, or duplicate `sequence` values.
- **Exposing the record.** The dashboard command listens on localhost only. The audit file is readable only by the user who owns it.

## Decided

### Recording is on by default

Decided by the maintainer. With no env var set, all three CLIs write to:

```
<LocalApplicationData>/ai-sentinel/audit.db
```

`Environment.SpecialFolder.LocalApplicationData` resolves to `~/.local/share` on Linux, `~/Library/Application Support` on macOS and `%LOCALAPPDATA%` on Windows. The directory is created on first write. *My call:* on Unix, create the directory 0700 and the file 0600.

### Env vars

*My call*, keeping the existing prefix families: hooks read `SENTINEL_HOOK_*` and the MCP proxy reads `SENTINEL_MCP_*`.

| Variable | Read by | Effect |
|---|---|---|
| `SENTINEL_HOOK_AUDIT_SQLITE` | both hook CLIs | Path of the SQLite file. `off` disables SQLite recording. Unset means the default path. |
| `SENTINEL_HOOK_AUDIT_NDJSON` | both hook CLIs | Path of an NDJSON file to append every entry to, as a forwarder. Unset means no NDJSON. |
| `SENTINEL_HOOK_AUDIT_MAX_MB` | both hook CLIs | Size cap for the SQLite file in MB. Default `100`; `0` means no cap. |
| `SENTINEL_MCP_AUDIT_SQLITE` | MCP proxy | Same as the hook variable. |
| `SENTINEL_MCP_AUDIT_NDJSON` | MCP proxy | Same as the hook variable. |
| `SENTINEL_MCP_AUDIT_MAX_MB` | MCP proxy | Same as the hook variable. |

With `..._AUDIT_SQLITE=off`, the CLI falls back to today's in-memory ring buffer, so the code paths stay the same.

### Source of each entry

Decided by the maintainer: every entry records which tool wrote it.

- Add `string? Source = null` to the public `AuditEntry` record, after `SessionId`. In-process apps leave it `null`, unless they choose to set it.
- The hook CLIs set `claude-code` and `copilot`, and the MCP proxy sets `mcp`. *My call:* the source is a property of the writer, so set it once, where the CLI builds its writer, and not at each call site.
- `AuditHashChain.ComputeHash` covers `Source`, so it is tamper-evident like every other field.
- SQLite schema v5 adds a nullable `source` column. The ring buffer needs nothing extra.
- The dashboard shows the source in the feed and in the NDJSON export, and can filter on it. How the filter looks is left to the builder; follow the existing chips and search.
- **Timing:** adding a positional record parameter breaks binary compatibility. This must merge before release PR #346 (3.0.0) is merged, so it ships in the same major version. If 3.0.0 has already been released when this is built, stop and ask.

### Size cap

Decided by the maintainer: a size cap, 100 MB by default.

- `SqliteAuditStoreOptions.MaxDatabaseSizeBytes` already exists. The CLIs set it from the env var.
- The existing sweep runs on an hourly timer, which a hook process never lives long enough to reach. *My call:* when a CLI opens the store and the database is over its cap, it trims once right then. The long-lived MCP proxy also keeps the timer.
- Trimming removes the oldest entries first, a prefix in append order, so the hash chain stays intact. This is how the size cap already works.
- *My call:* a hook process does not `VACUUM`. That would hold the cross-process write lock far longer than the busy timeout. Freed pages are reused by later inserts, so without `VACUUM` the file stops growing at about the cap instead of shrinking. Measure the size as used pages, page count minus free-list count times page size, and not as the file length, or the cap would trigger on every open. The MCP proxy's timer sweep may still `VACUUM`.

### Multi-process safety lives in `SqliteAuditStore`

*My call.* The root cause is that `SqliteAuditStore` caches `_sequence` and `_lastHash` in memory. That is correct for one writer and wrong for several processes. The fix belongs in the store, not in each CLI:

- `AppendAsync` begins its transaction with `BEGIN IMMEDIATE` (Microsoft.Data.Sqlite's `BeginTransaction()` already does this). Inside it, the store reads the chain head from `audit_chain_head` and the next `sequence` from the database instead of from the cache, then links, inserts and updates the head.
- The SQLite write lock then serialises writers across processes, and every process sees the latest head.
- Within one process, the in-memory `_writeLock` stays as it is.
- The schema migration on first open must also be safe when two processes open an out-of-date database at the same time. `SqliteSchema.cs` currently documents single-writer only. Either run the migration under `BEGIN IMMEDIATE` and re-check `user_version` inside the transaction, or document why concurrent first-open cannot happen.
- Update the "single-writer" statements in the docs to say multiple processes are supported.

### Failure handling

Decided by the anti-goals, and summarised here:

- **Opening the store fails** (permissions, corrupt file, migration error): write one line to stderr and continue with the in-memory ring buffer.
- **An append fails:** the CLIs wrap their store in a layer that never throws. It reports the failure and returns the entry unlinked, and the caller carries on with the decision it made. *My call:* this lives in the CLIs, not in `SentinelPipeline`. Detection entries are written inside the pipeline before a decision exists, so catching at the hook adapters would come too late. Changing the pipeline would change behaviour for in-process apps, which today fail the call when the audit write fails.
- **Where the failure is reported:** *my call*. On the Block and Warn paths, stderr is the reason text the agent hands back to the model, and the CLIs already keep diagnostics out of it. An audit failure must not ride along there, because it would tell the model, or someone driving it, that its actions are not being recorded. Report it on stderr only on the Allow path, and through the existing verbose output.
- **Busy timeout:** *my call*. Writers use a short busy timeout of about 2 seconds. A hook that cannot get the write lock in that time gives up on that entry and reports it on stderr rather than stalling the agent.

### Forwarders finish before a hook exits

Forwarding is fire-and-forget (`AuditForwarding`). A hook process that exits right after appending would drop the NDJSON copy. The hook CLIs must wait for in-flight forwards to finish, with a bounded wait of about 2 seconds, before they exit. The long-lived MCP proxy waits the same way on shutdown.

### `sentinel dashboard`

Decided by the maintainer: a command in the existing `AI.Sentinel.Cli` tool, next to `scan`.

```
sentinel dashboard [--db <path>] [--port <port>]
```

- `--db` defaults to the same default path as the CLIs.
- It hosts the existing `AI.Sentinel.AspNetCore` dashboard (`MapAISentinel`) on `http://127.0.0.1:<port>/`. *My call:* port 5170 by default, and if that port is busy, fail with a clear message.
- It prints the URL. *My call:* it does not open a browser automatically.
- It registers the SQLite store over the file and **no** `IApprovalStore`. The dashboard already shows "no approval store" in that case.
- It never appends entries, and it disables the retention timer and the size cap. *My call:* it opens the file through the normal store. That means it may migrate an older schema and may create the WAL side files, which a reader of a WAL database needs anyway. "Read-only" here means it never changes the audit record.
- If the file does not exist, it says so and exits non-zero rather than creating an empty database.
- On startup it runs `AuditHashChain.VerifyAsync` once and prints the result on the terminal: intact, with the entry count, or the first broken entry Id.

`AI.Sentinel.Cli` gains references to `AI.Sentinel.AspNetCore`, `AI.Sentinel.Sqlite` and the ASP.NET Core shared framework. *My call:* this is acceptable, because `dotnet tool` users have the SDK, which ships the ASP.NET Core runtime. Mention the requirement in the package description.

### Docs

- `claude-code.md` and `copilot.md`: describe the default file, the env vars including `off`, the NDJSON option, and `sentinel dashboard`.
- `claude-code.md`: fix the programmatic sample, which calls a nonexistent `adapter.RunAsync(stdin:, stdout:)`. Show `HookAdapter.HandleAsync`, or `HookPipelineRunner.RunAsync` with its real signature.
- `mcp-proxy.md`: add an audit section.
- `README.md` Art. 12 row: in-process apps still default to the ring buffer, and the CLIs now record durably by default. Say both.

## Left to the builder

- How the CLIs build the store. Registering `AddSentinelSqliteStore` in each `BuildProvider` is fine. For the MCP proxy, `McpPipelineFactory.Create` currently returns its own ring buffer (`src/AI.Sentinel.Mcp/McpPipelineFactory.cs:68`); passing the store in is fine.
- Whether the hooks share one helper for "resolve env vars, build store and forwarders, flush on exit" across the two hook CLIs, and how.
- How to signal that a write failed and was reported, in tests.
- The exact stderr wording.
- Whether `sentinel dashboard` uses minimal hosting (`WebApplication`) or something smaller.
- Native AOT: the hook CLIs and the MCP proxy publish AOT binaries, and the AOT publish workflow must stay green. `AI.Sentinel.Approvals.Sqlite` already uses Microsoft.Data.Sqlite in those binaries, so `AI.Sentinel.Sqlite` should be fine. Verify it.

## Testing expectations

- Several processes or tasks appending to one file concurrently give one intact chain, with unique sequence numbers.
- The hook on the deny path still returns Block when the audit file is unwritable.
- The default path is used when no env var is set; `off` disables recording; NDJSON gets every entry before the process exits.
- `sentinel dashboard` serves the feed from an existing file, refuses a missing file, and never appends entries.
- A CLI opening an over-cap file trims it below the cap and leaves an intact chain.
- Entries written by each tool carry the right `Source`; editing `source` in the file breaks verification.
