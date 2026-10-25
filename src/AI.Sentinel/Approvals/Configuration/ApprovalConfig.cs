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
    IReadOnlyDictionary<string, IReadOnlyList<ApprovalToolConfig>> Tools);
