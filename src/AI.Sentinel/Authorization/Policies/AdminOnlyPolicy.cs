using ZeroAlloc.Authorization;
using ZeroAlloc.Results;

namespace AI.Sentinel.Authorization.Policies;

/// <summary>Reference policy: allows callers with the <c>admin</c> role. Opt-in via DI registration.</summary>
[Policy("admin-only")]
public sealed class AdminOnlyPolicy : IAuthorizationPolicy
{
    /// <summary>Allows when <paramref name="ctx"/>'s roles contain <c>admin</c>; otherwise denies with
    /// <see cref="SentinelDenyCodes.PolicyDenied"/>.</summary>
    public ValueTask<UnitResult<AuthorizationFailure>> EvaluateAsync(
        ISecurityContext ctx, CancellationToken ct = default) =>
        new(ctx.Roles.Contains("admin")
            ? UnitResult<AuthorizationFailure>.Success()
            : UnitResult<AuthorizationFailure>.Failure(
                new AuthorizationFailure(SentinelDenyCodes.PolicyDenied, "Caller is not in the 'admin' role")));
}
