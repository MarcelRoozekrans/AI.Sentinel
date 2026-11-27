using AI.Sentinel.ClaudeCode.Events;
using AI.Sentinel.ClaudeCode.Policy.Rego;
using AI.Sentinel.ClaudeCode.Resident;
using AI.Sentinel.Profiles;
using AI.Sentinel.Tests.ClaudeCode.Resident;
using AI.Sentinel.Tests.Profiles;
using Xunit;

namespace AI.Sentinel.Tests.ClaudeCode.Events;

/// <summary>Detailed logging stops with the profile that turned it on, not at the next refresh (ADR-247).</summary>
[Collection("NonParallel")]
public sealed class DetailedLoggingSwitchTests : IDisposable
{
    private const string Org = "acme";
    private const string Repo = "github.com/acme/widgets";
    private static readonly DateTimeOffset Now = new(2026, 11, 23, 10, 0, 0, TimeSpan.Zero);

    private readonly string _dir = ResidentTestSupport.NewDir();

    public void Dispose()
    {
        ResidentTestSupport.Delete(_dir);
    }

    [Fact]
    public void A_kept_answer_ends_when_the_profile_expires()
    {
        var key = ProfileSigningKey.Generate();
        var pinned = PinnedProfileKeys.Create([key.PublicKey]);
        var state = new ResidentState(ResidentPaths.Prepare(new ResidentSettings(_dir, ResidentSettings.DefaultIdleTimeout, ResidentSettings.DefaultBudget)));
        var sample = SignedProfileTests.Sample();
        var signed = new ProfileSigner(key, new Clock(Now)).Issue(
            sample with
            {
                Organisation = Org,
                Repository = Repo,
                LoggingSwitches = new Dictionary<string, bool>(StringComparer.Ordinal) { ["detailed"] = true },
            },
            TimeSpan.FromSeconds(20));
        Assert.True(state.StoreProfile(signed, pinned, Org, Repo, Now).IsAccepted);
        var clock = new Clock(Now);
        var logging = new DetailedLoggingSwitch(_dir, () => (Org, pinned), clock);

        Assert.True(logging.IsOn(sample.Node));
        clock.Now = Now.AddSeconds(25);

        Assert.False(logging.IsOn(sample.Node));
    }

    [Fact]
    public void Without_a_node_or_without_pinned_keys_detailed_logging_is_off()
    {
        Directory.CreateDirectory(_dir);
        var pinned = PinnedProfileKeys.Create([ProfileSigningKey.Generate().PublicKey]);

        Assert.False(new DetailedLoggingSwitch(_dir, () => (Org, pinned), new Clock(Now)).IsOn(null));
        Assert.False(new DetailedLoggingSwitch(_dir, () => (Org, pinned), new Clock(Now)).IsOn(string.Empty));
        Assert.False(new DetailedLoggingSwitch(_dir, () => null, new Clock(Now)).IsOn("node-a"));
    }

    [Fact]
    public void A_cached_profile_that_cannot_be_read_says_nothing_and_another_one_still_counts()
    {
        var key = ProfileSigningKey.Generate();
        var pinned = PinnedProfileKeys.Create([key.PublicKey]);
        var state = new ResidentState(ResidentPaths.Prepare(new ResidentSettings(_dir, ResidentSettings.DefaultIdleTimeout, ResidentSettings.DefaultBudget)));
        var sample = SignedProfileTests.Sample();
        var signed = new ProfileSigner(key, new Clock(Now)).Issue(
            sample with
            {
                Organisation = Org,
                Repository = Repo,
                LoggingSwitches = new Dictionary<string, bool>(StringComparer.Ordinal) { ["detailed"] = true },
            },
            TimeSpan.FromMinutes(5));
        Assert.True(state.StoreProfile(signed, pinned, Org, Repo, Now).IsAccepted);
        // One file with no digest, one whose envelope is not a profile, one whose profile is not base64.
        File.WriteAllText(Path.Combine(_dir, "profile-raw.json"), signed.ToJson());
        PolicyCache.Write(Path.Combine(_dir, "profile-empty.json"), System.Text.Encoding.UTF8.GetBytes("{}"));
        PolicyCache.Write(Path.Combine(_dir, "profile-bad.json"), System.Text.Encoding.UTF8.GetBytes((signed with { Profile = "!not base64!" }).ToJson()));

        Assert.True(new DetailedLoggingSwitch(_dir, () => (Org, pinned), new Clock(Now)).IsOn(sample.Node));
    }

    private sealed class Clock(DateTimeOffset now) : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = now;

        public override DateTimeOffset GetUtcNow() => Now;
    }
}
