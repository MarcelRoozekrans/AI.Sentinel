---
sidebar_position: 2
title: NDJSON file
---

# NDJSON file forwarder

`NdjsonFileAuditForwarder` appends every audit entry as a JSON Lines record to a local file. Operators ship the file via Filebeat / Vector / Fluent Bit.

```csharp
services.AddSentinelNdjsonForwarder(new NdjsonFileAuditForwarderOptions
{
    FilePath = "/var/log/ai-sentinel/audit.ndjson"
});
```

LF line terminators on all platforms (Windows / Linux / macOS) for consistent SIEM ingestion.

> Full NDJSON forwarder guide — file rotation strategies, AOT-safe JSON serialization — coming soon.
