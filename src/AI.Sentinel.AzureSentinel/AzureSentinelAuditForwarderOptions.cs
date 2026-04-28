using Azure.Core;

namespace AI.Sentinel.AzureSentinel;

/// <summary>Configuration for <see cref="AzureSentinelAuditForwarder"/>.</summary>
public sealed class AzureSentinelAuditForwarderOptions
{
    /// <summary>Data Collection Endpoint URL (DCE).</summary>
    public Uri DcrEndpoint { get; set; } = null!;

    /// <summary>Immutable ID of the Data Collection Rule (DCR).</summary>
    public string DcrImmutableId { get; set; } = null!;

    /// <summary>Stream name within the DCR (target table).</summary>
    public string StreamName { get; set; } = null!;

    /// <summary>Auth credential. Defaults to <c>DefaultAzureCredential</c>.</summary>
    public TokenCredential? Credential { get; set; }
}
