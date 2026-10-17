using System.Text.Json.Serialization;

namespace AI.Sentinel.Cli.Report;

/// <summary>
/// Source-generated JSON metadata for <see cref="ComplianceReport"/>: camelCase properties and severities as names.
/// Generated rather than reflected, so the CLI stays trim and AOT safe.
/// </summary>
[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    WriteIndented = true,
    UseStringEnumConverter = true)]
[JsonSerializable(typeof(ComplianceReport))]
internal sealed partial class ComplianceReportJsonContext : JsonSerializerContext
{
}
