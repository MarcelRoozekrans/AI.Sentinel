using System.Text.Json;
using AI.Sentinel.Audit;
using AI.Sentinel.Profiles;

namespace AI.Sentinel.AspNetCore.AdminAudit;

/// <summary>What an auditor noted from an earlier export or verify run.</summary>
internal sealed record AdminAuditCheckpoint(long Count, string Hash, DateTimeOffset ExportedAt);
