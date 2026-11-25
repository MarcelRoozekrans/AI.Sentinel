using System.Text.Json;
using AI.Sentinel.Approvals;
using ZeroAlloc.Authorization;

namespace AI.Sentinel.ClaudeCode.ServerApprovals;

/// <summary>
/// The <c>http</c> approval backend (#662): an approval is requested on the server, decided there, and acted on by the hook when
/// the agent retries. The hook asks the server through the resident process, which holds the token.
/// <list type="bullet">
/// <item>The tool input goes to the server after AI.Sentinel's redaction (ADR-027), so the approver sees what they approve and no
/// secret leaves the PC. An input that cannot be redacted is withheld, never sent as it is.</item>
/// <item>Until a grant exists the state is pending, which the guard turns into a deny with a receipt that says the call waits for
/// approval. A server that cannot be reached, or that the developer is not signed in at, is a denial that says so (ADR-004).</item>
/// <item>The requester is the developer of the token, so the caller of the hook does not matter: nobody approves their own request.</item>
/// </list>
/// </summary>
/// <param name="channel">How the server is asked; <see langword="null"/> when the hook has no connection to it.</param>
/// <param name="redact">Redacts the tool input; <see langword="null"/> as a result means it could not be redacted.</param>
/// <param name="repository">The normalised git remote of the working directory, or empty outside git.</param>
/// <param name="time">The clock of the wait.</param>
/// <param name="pollInterval">How often <see cref="WaitForDecisionAsync"/> asks the server again.</param>
internal sealed class HttpApprovalStore(
    IApprovalChannel? channel, Func<JsonElement, JsonElement?> redact, string repository, TimeProvider? time = null, TimeSpan? pollInterval = null) : IApprovalStore
{
    /// <summary>Stands for a tool input that could not be redacted.</summary>
    internal const string WithheldInput = "[withheld by AI.Sentinel: the tool input could not be redacted]";

    internal const string UnreachableReason =
        "The AI.Sentinel approval server is unreachable, so this call is denied. Try again when the server can be reached.";

    internal const string SignInNeededReason =
        "You are not signed in to the AI.Sentinel approval server, so this call is denied. Run sentinel-hook --sign-in and try again.";

    internal const string RefusedReason = "The AI.Sentinel approval server refused the approval request, so this call is denied.";

    internal const string OffReason =
        "The AI.Sentinel approval server is unreachable from here: the resident process is not running or has no server. " +
        "Set SENTINEL_HOOK_RESIDENT=on and the server settings, then try again. This call is denied.";

    private static readonly TimeSpan DefaultPollInterval = TimeSpan.FromSeconds(2);

    private readonly TimeProvider _time = time ?? TimeProvider.System;

    public async ValueTask<ApprovalState> EnsureRequestAsync(
        ISecurityContext caller, ApprovalSpec spec, ApprovalContext context, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(spec);
        ArgumentNullException.ThrowIfNull(context);
        if (channel is null)
        {
            return Denied(OffReason);
        }

        var request = new ApprovalRequestWire
        {
            Repository = repository,
            Policy = spec.PolicyName,
            Tool = context.ToolName,
            Args = RedactedArgs(context.Args),
            Justification = context.Justification,
            Reason = context.Reason,
            GrantSeconds = (int)Math.Clamp(spec.GrantDuration.TotalSeconds, 1, int.MaxValue),
        };
        return ToState(await channel.EnsureAsync(request, ct).ConfigureAwait(false));
    }

    public async ValueTask<ApprovalState> WaitForDecisionAsync(string requestId, TimeSpan timeout, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(requestId);
        if (channel is null)
        {
            return Denied(OffReason);
        }

        var deadline = _time.GetUtcNow() + timeout;
        var interval = pollInterval ?? DefaultPollInterval;
        while (true)
        {
            var state = ToState(await channel.GetAsync(requestId, ct).ConfigureAwait(false));
            var remaining = deadline - _time.GetUtcNow();
            if (state is not ApprovalState.Pending || remaining <= TimeSpan.Zero)
            {
                return state;
            }

            // Wait out the rest of the timeout, not only whole poll intervals, then ask once more.
            await Task.Delay(remaining < interval ? remaining : interval, _time, ct).ConfigureAwait(false);
        }
    }

    private JsonElement? RedactedArgs(JsonElement args)
    {
        if (args.ValueKind is JsonValueKind.Undefined)
        {
            return null;
        }

        // An input that cannot be redacted is not sent: the approver is told so instead.
        return redact(args) ?? JsonSerializer.SerializeToElement(WithheldInput, ApprovalWireJsonContext.Default.String);
    }

    private ApprovalState ToState(ApprovalChannelReply reply)
    {
        switch (reply.Status)
        {
            case ApprovalChannelStatus.Ok when reply.State is { } wire:
                return FromWire(wire);
            case ApprovalChannelStatus.SignInNeeded:
                return Denied(SignInNeededReason);
            case ApprovalChannelStatus.Refused:
                return Denied(RefusedReason);
            case ApprovalChannelStatus.NotFound:
                return Denied("unknown request");
            case ApprovalChannelStatus.Off:
                return Denied(OffReason);
            default:
                return Denied(UnreachableReason);
        }
    }

    private ApprovalState FromWire(ApprovalStateWire wire)
    {
        switch (wire.State)
        {
            case ApprovalWireStates.Pending:
                return new ApprovalState.Pending(wire.Id, wire.ApprovalUrl, wire.RequestedAt) { IsNew = wire.IsNew, Reason = wire.RequestReason };
            case ApprovalWireStates.Active when wire.ExpiresAt is { } expires:
                return new ApprovalState.Active(expires) { RequestId = wire.Id };
            case ApprovalWireStates.Denied:
                return new ApprovalState.Denied(wire.Reason ?? "denied", wire.DecidedAt ?? _time.GetUtcNow()) { RequestId = wire.Id };
            default:
                return Denied("The AI.Sentinel approval server sent an answer this hook does not understand, so this call is denied.");
        }
    }

    private ApprovalState.Denied Denied(string reason) => new(reason, _time.GetUtcNow());
}
