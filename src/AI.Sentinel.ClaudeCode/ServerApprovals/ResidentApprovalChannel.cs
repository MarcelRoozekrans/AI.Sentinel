using AI.Sentinel.ClaudeCode.Resident;

namespace AI.Sentinel.ClaudeCode.ServerApprovals;

/// <summary>The hook side of the approval endpoints: asks the resident process, which holds the token and talks to the server. A
/// process that is missing, slow or has no server is an <see cref="ApprovalChannelStatus"/>, never an exception.</summary>
internal sealed class ResidentApprovalChannel(ResidentClient client, TimeSpan? budget = null) : IApprovalChannel
{
    /// <summary>A hook waits this long for the server through the resident process. It is longer than the budget of a policy
    /// decision, because it is a network call, and it is spent only when a call needs approval.</summary>
    public static readonly TimeSpan DefaultBudget = TimeSpan.FromSeconds(5);

    /// <summary>The <see cref="ResidentResponse.Error"/> of a resident process that has no server to ask.</summary>
    internal const string OffError = "approvals_off";

    public async Task<ApprovalChannelReply> EnsureAsync(ApprovalRequestWire request, CancellationToken ct) =>
        Reply(await client.SendAsync(new ResidentRequest { Op = ResidentOps.ApprovalEnsure, Approval = request }, budget ?? DefaultBudget).WaitAsync(ct).ConfigureAwait(false));

    public async Task<ApprovalChannelReply> GetAsync(string requestId, CancellationToken ct) =>
        Reply(await client.SendAsync(new ResidentRequest { Op = ResidentOps.ApprovalGet, RequestId = requestId }, budget ?? DefaultBudget).WaitAsync(ct).ConfigureAwait(false));

    private static ApprovalChannelReply Reply(ResidentResponse? response)
    {
        if (response is null)
        {
            return new ApprovalChannelReply(ApprovalChannelStatus.Unreachable);
        }

        if (response.Ok && response.Approval is { } state)
        {
            return new ApprovalChannelReply(ApprovalChannelStatus.Ok, state);
        }

        return response.Error switch
        {
            ResidentApprovalAnswer.SignInNeeded => new ApprovalChannelReply(ApprovalChannelStatus.SignInNeeded),
            ResidentApprovalAnswer.Refused => new ApprovalChannelReply(ApprovalChannelStatus.Refused),
            ResidentApprovalAnswer.NotFound => new ApprovalChannelReply(ApprovalChannelStatus.NotFound),
            OffError => new ApprovalChannelReply(ApprovalChannelStatus.Off),
            _ => new ApprovalChannelReply(ApprovalChannelStatus.Unreachable),
        };
    }
}
