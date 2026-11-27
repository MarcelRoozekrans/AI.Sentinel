namespace AI.Sentinel.ClaudeCode.ServerApprovals;

/// <summary>The requests an approver reads.</summary>
internal sealed record ApprovalListWire
{
    public IReadOnlyList<ApprovalListItemWire> Requests { get; init; } = [];
}
