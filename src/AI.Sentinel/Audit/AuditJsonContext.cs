using System.Text.Json.Serialization;

namespace AI.Sentinel.Audit;

/// <summary>Source-generated JSON context for audit serialisation (AOT-safe).</summary>
[JsonSourceGenerationOptions(
    WriteIndented = false,
    PropertyNamingPolicy = JsonKnownNamingPolicy.Unspecified,
    UseStringEnumConverter = true)]
[JsonSerializable(typeof(AuditEntry))]
internal sealed partial class AuditJsonContext : JsonSerializerContext;
