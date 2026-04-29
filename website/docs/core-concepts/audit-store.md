---
sidebar_position: 4
title: Audit store
---

# Audit store

`IAuditStore` is the append-only record of every detection. The default `RingBufferAuditStore` is in-process and bounded by `opts.AuditCapacity` (default 10,000 entries). For persistence, swap in `SqliteAuditStore` from `AI.Sentinel.Sqlite`.

Every entry is **hash-chained** — each entry includes the SHA-256 hash of the previous entry, so any tampering is detectable.

```csharp
public sealed record AuditEntry(
    string Id,
    DateTimeOffset Timestamp,
    string Hash,
    string? PreviousHash,
    Severity Severity,
    string DetectorId,
    string Summary);
```

> Full audit store guide — hash-chain verification, retention policies, query API, custom store implementations — coming soon. See also [Audit Forwarders](../audit-forwarders/overview).
