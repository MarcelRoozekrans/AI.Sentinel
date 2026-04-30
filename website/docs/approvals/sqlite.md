---
sidebar_position: 3
title: SQLite backend
---

# SQLite approval store

Persistent file-backed `IApprovalStore`. Survives process restarts. Ships in the **`AI.Sentinel.Approvals.Sqlite`** package and is bundled into the three CLIs (`sentinel-hook`, `sentinel-copilot-hook`, `sentinel-mcp`) so CLI operators get persistence without code changes.

## When to use it

- **CLI deployments** — each invocation is a fresh process, so in-memory wouldn't survive between calls. SQLite holds approvals until the human acts.
- **Single-host multi-process** — the dashboard process and the CLI process can share approval state via the same `.db` file (single-writer-per-host caveat applies).
- **You don't have Entra PIM** — SQLite is the no-Azure-dependency persistence option.

## Wiring (in-process)

```csharp
using AI.Sentinel.Approvals.Sqlite;

services.AddSentinelSqliteApprovalStore(opts =>
{
    opts.DatabasePath = "/var/lib/ai-sentinel/approvals.db";
});

services.AddAISentinel(opts =>
{
    opts.RequireApproval("delete_database", spec =>
    {
        spec.GrantDuration = TimeSpan.FromMinutes(15);
        spec.BackendBinding = "DBA";
    });
});
```

Order matters: register the SQLite store **before** `AddAISentinel`, otherwise the auto-register of `InMemoryApprovalStore` fires and the SQLite extension throws on duplicate registration.

## Wiring (CLI)

CLIs read [`SENTINEL_APPROVAL_CONFIG`](/docs/approvals/cli-config). Set the path to a JSON file:

```json
{
  "backend": "sqlite",
  "databasePath": "/var/lib/ai-sentinel/approvals.db",
  "defaultGrantMinutes": 15,
  "tools": {
    "delete_database": { "role": "DBA" }
  }
}
```

```bash
export SENTINEL_APPROVAL_CONFIG=/etc/ai-sentinel/approvals.json
sentinel-hook user-prompt-submit < input.json
```

## Schema and durability

- One table: `approval_requests`. Columns: `id`, `caller_id`, `policy_name`, `tool_name`, `args_json`, `justification`, `requested_at`, `grant_duration_ticks`, `status`, `approved_at`, `denied_at`, `deny_reason`, `approver_id`, `approver_note`. Index on `status`.
- `status` is one of `'Pending'`, `'Active'`, `'Denied'`. There is no separate `'Expired'` status — an expired grant is an `Active` row whose `approved_at + grant_duration_ticks` is in the past, projected to `Denied("expired")` by the store on the next observation.
- Migrations versioned via `PRAGMA user_version`.
- **Journal mode `WAL`** — concurrent readers don't block the writer; better crash safety. Leaves `-wal` and `-shm` sidecars next to the `.db` file; back them up together.

## Multi-process semantics

SQLite supports concurrent **readers** but only one **writer** at a time on a single host. Two CLI invocations writing simultaneously will serialize. Do **not** put the `.db` file on a network share — SQLite over NFS/SMB is unsafe.

## Polling

`SqliteApprovalStoreOptions.PollInterval` (default 500ms) controls how aggressively `WaitForDecisionAsync` polls the database. Lower values reduce wait latency; higher values reduce CPU/IO churn on slow disks.

## Cleanup

Settled requests stay in the table for audit. The store doesn't auto-prune — that's an operator policy decision. If you want a retention bound, run periodically against the column names above (`status`, `denied_at`, `approved_at`); the store doesn't lock the schema as a public contract, so prefer your normal SQLite admin tooling over the in-app surface.

After bulk deletes, reclaim disk space:

```sql
PRAGMA wal_checkpoint(TRUNCATE);
VACUUM;
```

## Approver UX

Same dashboard panel as in-memory — `SqliteApprovalStore` implements `IApprovalAdmin`. Mount the dashboard in any process that has access to the `.db` file.
