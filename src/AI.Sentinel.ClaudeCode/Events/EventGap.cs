using System.Text.Json.Serialization;

namespace AI.Sentinel.ClaudeCode.Events;

/// <summary>Entries the server will never get: pruned before they were sent, skipped after a server change, or in an audit file that
/// was replaced. A gap the forwarder has to report is kept in the cursor until the server took it, so a batch that is sent again
/// carries the same <see cref="Id"/>, and the server stores the gap once (#713).</summary>
internal sealed record EventGap
{
    /// <summary>The gap was pruned by the local retention.</summary>
    public const string PrunedCause = "pruned";

    /// <summary>The entries were routed for another server or organisation, so they were skipped (#723).</summary>
    public const string ServerChangeCause = "server_change";

    /// <summary>The audit file was replaced; what the old file still held is not known (#713).</summary>
    public const string AuditReplacedCause = "audit_replaced";

    [JsonPropertyName("id")]
    public string? Id { get; init; }

    /// <summary>How many entries; <see langword="null"/> when <see cref="Unknown"/>.</summary>
    [JsonPropertyName("pruned")]
    public int? Pruned { get; init; }

    /// <summary><see langword="true"/> when the number of entries is not known; otherwise left out.</summary>
    [JsonPropertyName("unknown")]
    public bool? Unknown { get; init; }

    [JsonPropertyName("cause")]
    public string? Cause { get; init; }

    [JsonPropertyName("node")]
    public string? Node { get; init; }
}
