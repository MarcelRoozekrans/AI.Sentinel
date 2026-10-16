namespace AI.Sentinel.Approvals.Configuration;

/// <summary>Per-tool binding inside <see cref="ApprovalConfig.Tools"/>.</summary>
internal sealed record ApprovalToolConfig(
    string Role,
    int? GrantMinutes,
    bool? RequireJustification);
