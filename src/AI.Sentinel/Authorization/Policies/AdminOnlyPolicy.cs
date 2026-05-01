using ZeroAlloc.Authorization;

namespace AI.Sentinel.Authorization.Policies;

/// <summary>Reference policy: allows callers with the <c>admin</c> role. Opt-in via DI registration.</summary>
[AuthorizationPolicy("admin-only")]
public sealed class AdminOnlyPolicy : IAuthorizationPolicy
{
    /// <summary>Returns true when <paramref name="ctx"/>'s roles contain <c>admin</c>.</summary>
    public bool IsAuthorized(ISecurityContext ctx) => ctx.Roles.Contains("admin");
}
