namespace AI.Sentinel.Authorization;

/// <summary>Caller identity for authorization decisions. Mirrors the shape planned for ZeroAlloc.Mediator.Authorization.</summary>
public interface ISecurityContext
{
    /// <summary>Stable caller identifier — user, agent, or service name.</summary>
    string Id { get; }

    /// <summary>Role membership of the caller. Empty for anonymous callers.</summary>
    IReadOnlySet<string> Roles { get; }

    /// <summary>Optional claims (tenant, scope, sub, etc.). Empty by default.</summary>
    IReadOnlyDictionary<string, string> Claims { get; }
}
