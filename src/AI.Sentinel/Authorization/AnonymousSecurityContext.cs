using System.Collections.Frozen;

namespace AI.Sentinel.Authorization;

/// <summary>Singleton anonymous caller — no Id, no roles, no claims. Default when no provider configured.</summary>
public sealed class AnonymousSecurityContext : ISecurityContext
{
    /// <summary>Shared singleton instance used whenever no caller identity is configured.</summary>
    public static readonly AnonymousSecurityContext Instance = new();

    private AnonymousSecurityContext() { }

    /// <inheritdoc />
    public string Id => "anonymous";

    /// <inheritdoc />
    public IReadOnlySet<string> Roles { get; } = FrozenSet<string>.Empty;

    /// <inheritdoc />
    public IReadOnlyDictionary<string, string> Claims { get; } = FrozenDictionary<string, string>.Empty;
}
