using System.Globalization;
using System.Text;
using System.Text.Json.Serialization;

namespace AI.Sentinel.AspNetCore.AdminAudit;

/// <summary>The signed head. The signature covers <see cref="SigningBytes"/>, so a cut-off export no longer matches it.</summary>
internal sealed class AdminAuditHead
{
    private const string Domain = "ai-sentinel/admin-audit-head/v1";

    [JsonPropertyName("organisation")]
    public string? Organisation { get; init; }

    [JsonPropertyName("count")]
    public long Count { get; init; }

    [JsonPropertyName("last_hash")]
    public string? LastHash { get; init; }

    [JsonPropertyName("exported_at")]
    public string? ExportedAt { get; init; }

    [JsonPropertyName("key_id")]
    public string? KeyId { get; init; }

    [JsonPropertyName("signature")]
    public string? Signature { get; init; }

    public static string FormatTime(DateTimeOffset value) =>
        value.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'", CultureInfo.InvariantCulture);

    public static bool TryParseTime(string? text, out DateTimeOffset value) =>
        DateTimeOffset.TryParseExact(text, "yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'", CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out value);

    /// <summary>The bytes that are signed: a domain tag, then organisation, count, last hash and export time, one per line.</summary>
    public static byte[] SigningBytes(string organisation, long count, string? lastHash, string exportedAt) =>
        Encoding.UTF8.GetBytes(string.Join("\n", (IEnumerable<string>)[Domain, organisation, count.ToString(CultureInfo.InvariantCulture), lastHash ?? string.Empty, exportedAt]));
}
