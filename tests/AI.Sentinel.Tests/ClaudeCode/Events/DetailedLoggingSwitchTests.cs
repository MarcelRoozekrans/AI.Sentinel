using AI.Sentinel.ClaudeCode.Events;
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

    private sealed class Clock(DateTimeOffset now) : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = now;

        public override DateTimeOffset GetUtcNow() => Now;
    }
}
