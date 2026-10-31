namespace AI.Sentinel.Approvals.Configuration;

/// <summary>
/// Root config object loaded from <c>SENTINEL_APPROVAL_CONFIG</c> path. See design doc §9.1
/// for the JSON shape this maps to.
/// </summary>
internal sealed record ApprovalConfig(
    string Backend,
    string? TenantId,
    string? DatabasePath,
    int DefaultGrantMinutes,
    string DefaultJustificationTemplate,
    bool IncludeConversationContext,
    IReadOnlyDictionary<string, IReadOnlyList<ApprovalToolConfig>> Tools)
{
    /// <summary>Endpoint that receives a POST when an approval request is created. Null turns the feature off.</summary>
    public Uri? NotifyUrl { get; init; }

    /// <summary>Extra headers sent with the notification. Never null; header names compare case-insensitively.</summary>
    public IReadOnlyDictionary<string, string> NotifyHeaders { get; init; } =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    /// <summary>Whether the notification carries the tool call arguments.</summary>
    public bool NotifyIncludeArgs { get; init; }

    /// <summary>Base URL of the dashboard, used to link a notification to its request.</summary>
    public Uri? DashboardUrl { get; init; }
}
