---
sidebar_position: 3
title: SQLite
---

# SQLite audit store

`AI.Sentinel.Sqlite` ships `SqliteAuditStore` — a persistent `IAuditStore` backed by a single-file SQLite database with hash-chain integrity preserved across process restarts.

```csharp
services.AddSentinelSqliteAuditStore(new SqliteAuditStoreOptions
{
    DatabasePath = "/var/lib/ai-sentinel/audit.db",
    RetentionPeriod = TimeSpan.FromDays(90),
    RetentionSweepInterval = TimeSpan.FromHours(1),
});
```

Background timer-driven retention sweep deletes entries older than `RetentionPeriod`.

> Full SQLite store guide — schema migrations, query API, retention tuning, multi-instance considerations — coming soon.
