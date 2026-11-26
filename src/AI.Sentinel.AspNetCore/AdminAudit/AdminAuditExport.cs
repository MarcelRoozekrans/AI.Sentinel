using System.Globalization;
using System.Text;
using System.Text.Json.Serialization;

namespace AI.Sentinel.AspNetCore.AdminAudit;

/// <summary>The export of one organisation's log: its entries oldest first, then the signed head.</summary>
internal sealed class AdminAuditExport
{
    [JsonPropertyName("organisation")]
    public string? Organisation { get; init; }

    [JsonPropertyName("entries")]
    public List<AdminAuditEntryWire>? Entries { get; init; }

    [JsonPropertyName("head")]
    public AdminAuditHead? Head { get; init; }
}
