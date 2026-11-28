using AI.Sentinel.ClaudeCode.Policy.Rego;
using AI.Sentinel.ClaudeCode.Resident;
using AI.Sentinel.Profiles;

namespace AI.Sentinel.ClaudeCode.Policy.Repository;

/// <summary>
/// What the server decides about one hook call (#729): the repository policy, which judges the call by the signed profiles of the
/// organisation and of the node that owns the repository, and the fail mode for a call that no profile can decide. Both are read from
/// the state folder, with no network, once per call.
/// </summary>
/// <param name="Repository">The repository policy; <see langword="null"/> when nothing is resolved and the input names no repository.</param>
/// <param name="FailMode">The fail mode; <see langword="null"/> without a server, and then nothing changes.</param>
internal sealed record HookProfiles(RepositoryPolicy? Repository, FailModeContext? FailMode)
{
    /// <summary>
    /// The profiles of a hook call. Without a server configured nothing changes: a node map cached for the resident process gives the
    /// repository and the node, and no profile judges the call. With a server configured the keys pinned at sign-in check the cached
    /// profiles: a PC that has not signed in gets <see cref="FailModeContext.NotSignedIn"/>, one without a node map
    /// <see cref="FailModeContext.NoNodeMap"/>, and otherwise the profiles judge the call, the resident process first and then this
    /// process, and the fail mode is that of the profile that is missing, unusable or, when all are usable, applies.
    /// </summary>
    /// <param name="env">The <c>SENTINEL_HOOK_</c> settings.</param>
    /// <param name="workingDirectory">The working directory of the hook.</param>
    /// <param name="resident">The resident process; <see langword="null"/> when it is off, and then every profile is evaluated here.</param>
    /// <param name="compilers">The compilers for a profile module that is not compiled yet.</param>
    /// <exception cref="InvalidDataException">The cached node map cannot be read; the hook blocks the call.</exception>
    /// <exception cref="UnauthorizedAccessException">The state folder is open to other users; the hook blocks the call.</exception>
    public static HookProfiles Open(
        IReadOnlyDictionary<string, string?> env, string workingDirectory, ResidentSession? resident, IReadOnlyList<IRegoCompiler>? compilers)
    {
        ArgumentNullException.ThrowIfNull(env);
        resident?.ThrowIfUnusable();
        if (!ServerConfigured(env))
        {
            return new HookProfiles(WithoutServer(env, workingDirectory), null);
        }

        // The sign-in pins the keys in the state folder whether or not the resident process is on, so the folder is read either way.
        var state = ResidentState.Open(resident?.Settings ?? ResidentSettings.Always(env));
        if (state.ReadPinnedKeys() is not { } pinned)
        {
            return new HookProfiles(null, FailModeContext.NotSignedIn);
        }

        if (state.ReadNodeMap() is not { } map)
        {
            return new HookProfiles(null, FailModeContext.NoNodeMap);
        }

        var scope = RepositoryScope.Resolve(workingDirectory, map, RepositoryScope.StrictFrom(env));
        var now = DateTimeOffset.UtcNow;
        var policies = new CachedNodePolicies(
            state, pinned.Keys, pinned.Organisation, () => now, ProfileDecider.CompiledDirectory(state), compilers, resident);
        return new HookProfiles(new RepositoryPolicy(scope, policies), FailModeOf(policies, scope));
    }

    /// <summary>True when a server is set, or sign-in settings are set that cannot be used: a profile is expected then, and a missing
    /// one must not read as no server.</summary>
    private static bool ServerConfigured(IReadOnlyDictionary<string, string?> env) =>
        SignIn.SignInSettings.FromEnvironment(env, out var problem) is not null || problem is not null;

    // A cached map is only written once the PC has a server, so without one this is what it was before #729.
    private static RepositoryPolicy? WithoutServer(IReadOnlyDictionary<string, string?> env, string workingDirectory) =>
        RepositoryScope.Open(env, workingDirectory) is { } scope ? new RepositoryPolicy(scope, NoNodePolicies.Instance) : null;

    // The organisation's rules judge every call and the node's bundle the calls in the repositories it owns, so a profile of either that
    // cannot be used leaves part of the policy out: that profile gives the fail mode. When both are usable the node's fail mode applies
    // in its repositories, and the organisation's elsewhere.
    private static FailModeContext FailModeOf(CachedNodePolicies policies, RepositoryScope scope)
    {
        var organisation = policies.Verification(CachedNodePolicies.OrganisationRepository);
        if (scope.Unowned || organisation is not { IsAccepted: true })
        {
            return ContextOf(organisation);
        }

        return ContextOf(policies.Verification(scope.Repository));
    }

    private static FailModeContext ContextOf(ProfileVerification? verification) =>
        verification is null ? FailModeContext.NoProfile : FailModeContext.From(verification);
}
