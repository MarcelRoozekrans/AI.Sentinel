using AI.Sentinel.ClaudeCode.Policy.Rego;
using AI.Sentinel.ClaudeCode.Resident;
using AI.Sentinel.Profiles;

namespace AI.Sentinel.ClaudeCode.Policy.Repository;

/// <summary>
/// The policies from the signed profiles in the state folder, checked as <see cref="ProfileDecider"/> checks them. The organisation's
/// top-level rules are the profile issued for <see cref="OrganisationRepository"/>; a node's bundle is the profile issued for the
/// repository it owns. A profile that fails its check is not used. A profile that passes is evaluated by the resident process first,
/// which keeps its module warm, and in this process when that gives no answer (#729). A module that fails while it runs, in either
/// place, throws <see cref="PolicyBundleException"/>; one that failed in the resident process is not run again here (ADR-237, #716).
/// </summary>
internal sealed class CachedNodePolicies(
    ResidentState state, PinnedProfileKeys pinned, string organisation, Func<DateTimeOffset> now, string cacheDirectory,
    IReadOnlyList<IRegoCompiler>? compilers, IResidentProfiles? resident = null) : INodePolicies
{
    /// <summary>The repository value of the profile that holds the organisation's top-level rules.</summary>
    public const string OrganisationRepository = "*";

    // Checked once per repository: one hook call judges one call, and the fail mode and the decision must read the same profile.
    private readonly Dictionary<string, ProfileVerification?> _checked = new(StringComparer.Ordinal);

    /// <summary>The cache slot of the profile of <paramref name="repository"/>.</summary>
    public static string SlotOf(string repository) =>
        Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(repository)))[..16];

    public RegoDecision? Organisation(string inputJson) => Decide(OrganisationRepository, inputJson);

    public RegoDecision? ForRepository(string repository, string inputJson) => Decide(repository, inputJson);

    /// <summary>The check of the cached profile of <paramref name="repository"/>; <see langword="null"/> when none is cached.</summary>
    public ProfileVerification? Verification(string repository)
    {
        if (!_checked.TryGetValue(repository, out var verification))
        {
            verification = state.ReadProfile(pinned, organisation, repository, now(), SlotOf(repository));
            _checked[repository] = verification;
        }

        return verification;
    }

    private RegoDecision? Decide(string repository, string inputJson)
    {
        if (Verification(repository) is not { IsAccepted: true, Profile: { } profile })
        {
            return null;
        }

        return resident?.Evaluate(repository, profile.ModuleHash, inputJson)
            ?? ProfileDecider.Evaluate(state, profile, inputJson, cacheDirectory, compilers);
    }
}
