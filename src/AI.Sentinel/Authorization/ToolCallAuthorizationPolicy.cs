using ZeroAlloc.Authorization;

namespace AI.Sentinel.Authorization;

/// <summary>Ergonomic base for arg-aware tool-call policies. Allows automatically when context is not a tool call.</summary>
public abstract class ToolCallAuthorizationPolicy : IAuthorizationPolicy
{
    /// <summary>Allows automatically when <paramref name="ctx"/> is not a tool call; otherwise delegates to the typed overload.</summary>
    public bool IsAuthorized(ISecurityContext ctx) =>
        ctx is IToolCallSecurityContext tc ? IsAuthorized(tc) : true;

    /// <summary>Implement to authorize a tool call against its tool name + args.</summary>
    protected abstract bool IsAuthorized(IToolCallSecurityContext ctx);
}
