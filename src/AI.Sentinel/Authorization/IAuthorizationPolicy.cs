namespace AI.Sentinel.Authorization;

/// <summary>Pluggable authorization rule. Same shape as planned ZeroAlloc.Mediator.Authorization — one policy class works for both worlds.</summary>
public interface IAuthorizationPolicy
{
    /// <summary>Returns true if the caller is allowed. For tool calls, downcast <paramref name="ctx"/> to <see cref="IToolCallSecurityContext"/> for tool name + args.</summary>
    bool IsAuthorized(ISecurityContext ctx);
}
