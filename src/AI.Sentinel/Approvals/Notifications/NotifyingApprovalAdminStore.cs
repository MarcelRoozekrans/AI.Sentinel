using Microsoft.Extensions.Logging;

namespace AI.Sentinel.Approvals.Notifications;

/// <summary><see cref="NotifyingApprovalStore"/> over a store with an admin surface, which it forwards.</summary>
internal sealed class NotifyingApprovalAdminStore : NotifyingApprovalStore, IApprovalAdmin
{
    private readonly IApprovalAdmin _admin;

    internal NotifyingApprovalAdminStore(
        IApprovalStore inner, ApprovalNotifierSettings settings, HttpMessageHandler handler, ILogger? logger)
        : base(inner, settings, handler, logger)
    {
        _admin = inner as IApprovalAdmin
            ?? throw new ArgumentException("The inner store has no admin surface.", nameof(inner));
    }

    public ValueTask ApproveAsync(string requestId, string approverId, string? note, CancellationToken ct) =>
        _admin.ApproveAsync(requestId, approverId, note, ct);

    public ValueTask DenyAsync(string requestId, string approverId, string reason, CancellationToken ct) =>
        _admin.DenyAsync(requestId, approverId, reason, ct);

    public IAsyncEnumerable<PendingRequest> ListPendingAsync(CancellationToken ct) => _admin.ListPendingAsync(ct);
}
