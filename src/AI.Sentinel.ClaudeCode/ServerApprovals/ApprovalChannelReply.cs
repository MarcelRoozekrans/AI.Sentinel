namespace AI.Sentinel.ClaudeCode.ServerApprovals;

/// <summary>The answer of an <see cref="IApprovalChannel"/>.</summary>
internal sealed record ApprovalChannelReply(ApprovalChannelStatus Status, ApprovalStateWire? State = null);
