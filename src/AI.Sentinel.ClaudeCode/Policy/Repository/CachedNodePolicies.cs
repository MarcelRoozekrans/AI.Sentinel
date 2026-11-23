using AI.Sentinel.ClaudeCode.Policy.Rego;
using AI.Sentinel.ClaudeCode.Resident;
using AI.Sentinel.Profiles;

namespace AI.Sentinel.ClaudeCode.Policy.Repository;

/// <summary>
/// The policies from the signed profiles in the state folder, checked as <see cref="ProfileDecider"/> checks them. The organisation's
/// top-level rules are the profile issued for <see cref="OrganisationRepository"/>; a node's bundle is the profile issued for the
/// repository it owns. A profile that fails its check is not used.
/// </summary>
internal sealed class CachedNodePolicies(
    ResidentState state, PinnedProfileKeys pinned, string organisation, Func<DateTimeOffset> now, string cacheDirectory,
    IReadOnlyList<IRegoCompiler>? compilers) : INodePolicies
{
    /// <summary>The repository value of the profile that holds the organisation's top-level rules.</summary>
    public const string OrganisationRepository = "*";

    /// <summary>The cache slot of the profile of <paramref name="repository"/>.</summary>
    public static string SlotOf(string repository) =>
        Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(repository)))[..16];

    public RegoDecision? Organisation(string inputJson) => Decide(OrganisationRepository, inputJson);

    public RegoDecision? ForRepository(string repository, string inputJson) => Decide(repository, inputJson);

    private RegoDecision? Decide(string repository, string inputJson) =>
        ProfileDecider.Decide(state, pinned, organisation, repository, now(), inputJson, cacheDirectory, compilers, SlotOf(repository)).Decision;
}
