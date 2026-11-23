using AI.Sentinel.Profiles;

namespace AI.Sentinel.AspNetCore.PolicyFolder;

/// <summary>Builds and signs the profile of one repository from the configuration in force (ADR-233).</summary>
internal sealed class ProfileIssuer(PolicyFolderLoader loader, ProfileSigner signer, ProfileSigningKeys keys)
{
    /// <summary>The public keys a plugin pins, base64.</summary>
    public IReadOnlyList<string> PublicKeys() => [Convert.ToBase64String(keys.Current.PublicKey)];

    /// <summary>The signed profile of <paramref name="repository"/>, as asked for.</summary>
    /// <returns><see langword="null"/> when no node owns the repository.</returns>
    public SignedProfile? Issue(PublishedConfiguration configuration, string repository)
    {
        var node = configuration.Nodes.NodeFor(repository);
        if (node is null)
        {
            return null;
        }

        var profile = new PolicyProfile
        {
            Organisation = configuration.Organisation,
            Repository = repository.Trim(),
            Node = node.Id,
            ConfigurationVersion = configuration.Version,
            ModuleHash = configuration.ModuleHash,
            Module = configuration.Module,
            FailMode = node.FailMode,
            SeverityDefaults = node.SeverityDefaults,
            LoggingSwitches = new Dictionary<string, bool>(StringComparer.Ordinal) { ["detailed"] = node.DetailedLogging },
            IssuedAt = default,
            ExpiresAt = default,
        };
        return signer.Issue(profile, node.ProfileLifetime);
    }

    public PublishedConfiguration? Current => loader.Current;
}
