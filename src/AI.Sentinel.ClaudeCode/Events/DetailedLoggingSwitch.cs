using AI.Sentinel.ClaudeCode.Policy.Rego;
using AI.Sentinel.Profiles;

namespace AI.Sentinel.ClaudeCode.Events;

/// <summary>
/// Whether a node turned on detailed logging (ADR-247). The node's signed profile carries it as the <c>detailed</c> logging switch,
/// and the state folder keeps the last valid profile of each repository. Only a profile that passes the check counts, and a node with
/// none is off, so a reason is never sent on a guess. The answer is kept for a short while, so one batch does not read every file again.
/// </summary>
internal sealed class DetailedLoggingSwitch(string directory, Func<(string Organisation, PinnedProfileKeys Keys)?> pinned, TimeProvider time)
{
    private static readonly TimeSpan Keep = TimeSpan.FromSeconds(30);

    private readonly Lock _gate = new();
    private DateTimeOffset _readAt;
    private Dictionary<string, DateTimeOffset> _on = new(StringComparer.Ordinal);

    /// <summary>True when <paramref name="node"/> has detailed logging on.</summary>
    public bool IsOn(string? node)
    {
        if (string.IsNullOrEmpty(node))
        {
            return false;
        }

        lock (_gate)
        {
            var now = time.GetUtcNow();
            if (_readAt == default || now - _readAt > Keep)
            {
                _on = Read(now);
                _readAt = now;
            }

            // A kept answer ends with the profile that gave it, not after the next refresh.
            return _on.TryGetValue(node, out var expires) && now < expires;
        }
    }

    private Dictionary<string, DateTimeOffset> Read(DateTimeOffset now)
    {
        var on = new Dictionary<string, DateTimeOffset>(StringComparer.Ordinal);
        if (pinned() is not { } trusted || !System.IO.Directory.Exists(directory))
        {
            return on;
        }

        foreach (var file in System.IO.Directory.EnumerateFiles(directory, "profile*.json"))
        {
            try
            {
                if (PolicyCache.TryRead(file) is not { } bytes
                    || SignedProfile.Parse(System.Text.Encoding.UTF8.GetString(bytes)) is not { } signed
                    || ProfileCanonicalJson.Deserialize(Convert.FromBase64String(signed.Profile)) is not { } claimed)
                {
                    continue;
                }

                var verified = ProfileVerifier.Verify(signed, trusted.Keys, trusted.Organisation, claimed.Repository, now);
                if (verified.Profile is { } profile && profile.LoggingSwitches.GetValueOrDefault("detailed"))
                {
                    on[profile.Node] = on.TryGetValue(profile.Node, out var known) && known > profile.ExpiresAt ? known : profile.ExpiresAt;
                }
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException or FormatException)
            {
                // A file that cannot be read says nothing, which is off.
            }
        }

        return on;
    }
}
