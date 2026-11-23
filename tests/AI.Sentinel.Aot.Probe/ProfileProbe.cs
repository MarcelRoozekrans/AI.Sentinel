using AI.Sentinel.Profiles;

namespace AI.Sentinel.Aot.Probe;

// Signs and verifies a profile so Native AOT compiles and runs the Ed25519 code and the source-generated profile
// JSON. No CLI uses signed profiles yet, and without a root the trimmer would drop them. The native CLI workflow
// publishes this probe and runs it on Windows, Linux and macOS.
internal static class ProfileProbe
{
    public static bool Run()
    {
        var key = ProfileSigningKey.Generate();
        var pins = PinnedProfileKeys.Create([key.PublicKey]);
        var profile = new PolicyProfile
        {
            Organisation = "acme",
            Repository = "github.com/acme/widgets",
            Node = "node-1",
            ConfigurationVersion = 1,
            ModuleHash = "sha256:abc",
            Module = "package sentinel",
            FailMode = ProfileFailModes.Closed,
            SeverityDefaults = new Dictionary<string, string>(StringComparer.Ordinal) { ["high"] = "block" },
            LoggingSwitches = new Dictionary<string, bool>(StringComparer.Ordinal) { ["audit"] = true },
            IssuedAt = DateTimeOffset.UnixEpoch,
            ExpiresAt = DateTimeOffset.UnixEpoch.AddDays(1),
        };

        var signed = new ProfileSigner(key).Issue(profile);
        var cached = SignedProfile.Parse(signed.ToJson());
        if (cached is null)
        {
            return false;
        }
        var now = DateTimeOffset.UtcNow;
        var accepted = ProfileVerifier.Verify(cached, pins, "acme", "github.com/acme/widgets", now);
        var wrongKey = ProfileVerifier.Verify(cached, PinnedProfileKeys.Empty, "acme", "github.com/acme/widgets", now);
        return accepted.IsAccepted && wrongKey.Rejection == ProfileRejection.UnknownKey;
    }
}
