using ZeroAlloc.Authorization;
using ZeroAlloc.Results;

namespace AI.Sentinel.Authorization;

/// <summary>Ergonomic base for arg-aware tool-call policies. Allows automatically when context is not a tool call.</summary>
public abstract class ToolCallAuthorizationPolicy : IAuthorizationPolicy
{
    /// <summary>Allows automatically when <paramref name="ctx"/> is not a tool call; otherwise delegates to the typed overload.</summary>
    public ValueTask<UnitResult<AuthorizationFailure>> EvaluateAsync(
        ISecurityContext ctx, CancellationToken ct = default) =>
        ctx is IToolCallSecurityContext tc
            ? EvaluateAsync(tc, ct)
            : new ValueTask<UnitResult<AuthorizationFailure>>(Allow());

    /// <summary>Implement to authorize a tool call against its tool name + args.</summary>
    /// <remarks>Synchronous implementations can wrap their result in <c>new(...)</c> — a completed
    /// <see cref="ValueTask{TResult}"/> does not allocate.</remarks>
    protected abstract ValueTask<UnitResult<AuthorizationFailure>> EvaluateAsync(
        IToolCallSecurityContext ctx, CancellationToken ct);

    /// <summary>Permits the call.</summary>
    protected static UnitResult<AuthorizationFailure> Allow() => UnitResult<AuthorizationFailure>.Success();

    /// <summary>Refuses the call with a human-readable reason and a machine-readable code.</summary>
    /// <param name="reason">Human-readable reason, surfaced to audit and hook receipts.</param>
    /// <param name="code">Machine-readable code; defaults to <see cref="SentinelDenyCodes.PolicyDenied"/>.</param>
    protected static UnitResult<AuthorizationFailure> Deny(
        string reason, string code = SentinelDenyCodes.PolicyDenied) =>
        UnitResult<AuthorizationFailure>.Failure(new AuthorizationFailure(code, reason));
}
