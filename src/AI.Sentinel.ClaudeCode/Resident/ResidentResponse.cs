using System.Text.Json.Serialization;

namespace AI.Sentinel.ClaudeCode.Resident;

/// <summary>The answer to a <see cref="ResidentRequest"/>.</summary>
internal sealed record ResidentResponse
{
    /// <summary>True when the request was understood and carried out.</summary>
    [JsonPropertyName("ok")]
    public bool Ok { get; init; }

    /// <summary>The process id of the resident process.</summary>
    [JsonPropertyName("pid")]
    public int Pid { get; init; }

    /// <summary>Why the request failed; never a secret.</summary>
    [JsonPropertyName("error")]
    public string? Error { get; init; }

    /// <summary>For an evaluation: true when the bundle failed while it ran (#716). <see cref="Error"/> then holds the type of the
    /// error only. A hook denies that by bundle name and asks no other place; any other failure is no answer.</summary>
    [JsonPropertyName("bundle_error")]
    public bool BundleError { get; init; }

    /// <summary>For an evaluation: the outcome name.</summary>
    [JsonPropertyName("outcome")]
    public string? Outcome { get; init; }

    /// <summary>For an evaluation: the reasons of the outcome.</summary>
    [JsonPropertyName("reasons")]
    public IReadOnlyList<string>? Reasons { get; init; }

    /// <summary>For an evaluation: the builtin the call met that the host does not run.</summary>
    [JsonPropertyName("refused")]
    public string? Refused { get; init; }

    /// <summary>For an evaluation: the outcomes the policy sets per severity.</summary>
    [JsonPropertyName("severities")]
    public IReadOnlyList<ResidentSeverity>? Severities { get; init; }

    /// <summary>For the approval operations: the state the server answered. <see cref="Error"/> then holds a <see cref="ResidentApprovalAnswer"/>
    /// when there is none.</summary>
    [JsonPropertyName("approval")]
    public ServerApprovals.ApprovalStateWire? Approval { get; init; }

    /// <summary>For the sign-in operations: <c>signed_in</c>, <c>sign_in_needed</c>, or <c>off</c> when sign-in is not configured.</summary>
    [JsonPropertyName("sign_in")]
    public string? SignIn { get; init; }

    /// <summary>For a sign-in the resident took: what its keychain holds now, <c>kept</c>, <c>memory_only</c> or <c>earlier_remains</c>.</summary>
    [JsonPropertyName("keychain")]
    public string? Keychain { get; init; }
}
