namespace AI.Sentinel.ClaudeCode.Policy.Repository;

/// <summary>
/// The repository a call runs in and the node that owns it. A repository no node owns, or a folder outside git, is <see cref="Strict"/>
/// when strict repository mode is on, which is the default: it gets the organisation's top-level rules only and sends no events.
/// </summary>
/// <param name="Repository">The normalised name of the git remote; empty outside git. Never holds credentials.</param>
/// <param name="Node">The owning node; empty when none owns the repository.</param>
/// <param name="StrictMode">Whether strict repository mode is on.</param>
internal sealed record RepositoryScope(string Repository, string Node, bool StrictMode)
{
    /// <summary>The environment variable that turns strict repository mode off: <c>off</c>, <c>0</c>, <c>false</c> or <c>no</c>.</summary>
    public const string StrictVariable = "SENTINEL_HOOK_STRICT_REPOSITORY";

    /// <summary>True when no node owns the repository.</summary>
    public bool Unowned => Node.Length == 0;

    /// <summary>True when only the organisation's top-level rules apply: the repository is unowned and strict mode is on.</summary>
    public bool Strict => StrictMode && Unowned;

    /// <summary>False in strict repository mode: such a call sends no events.</summary>
    public bool SendsEvents => !Strict;

    /// <summary>Whether strict repository mode is on in <paramref name="env"/>; on unless it is switched off.</summary>
    public static bool StrictFrom(IReadOnlyDictionary<string, string?> env) => HookConfig.ParseSwitch(env, StrictVariable) ?? true;

    /// <summary>Resolves the scope of <paramref name="workingDirectory"/> from the git files and the cached <paramref name="map"/>.</summary>
    public static RepositoryScope Resolve(string workingDirectory, NodeMap map, bool strictMode)
    {
        ArgumentNullException.ThrowIfNull(map);
        var repository = RepositoryUrl.Normalize(GitRemote.UrlOf(workingDirectory)) ?? "";
        var node = repository.Length == 0 ? null : map.NodeFor(repository);
        return new RepositoryScope(repository, node ?? "", strictMode);
    }

    /// <summary>What the plugin tells the developer at session start when the repository is in strict mode, or <see langword="null"/>.</summary>
    public string? Notice() => !Strict ? null : Repository.Length == 0
        ? "AI.Sentinel: this folder is not in a git repository, so only the organisation's top-level rules apply and no events are sent."
        : "AI.Sentinel: no node owns this repository, so only the organisation's top-level rules apply and no events are sent.";
}
