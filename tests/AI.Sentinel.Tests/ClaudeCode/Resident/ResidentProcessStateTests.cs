using System.Text.Json;
using AI.Sentinel.ClaudeCode;
using AI.Sentinel.ClaudeCode.Policy;
using AI.Sentinel.ClaudeCode.Policy.Rego;
using AI.Sentinel.ClaudeCode.Resident;
using AI.Sentinel.Profiles;
using AI.Sentinel.Tests.Profiles;
using AI.Sentinel.Tests.ClaudeCode.Policy;
using AI.Sentinel.Tests.Helpers;
using Xunit;

namespace AI.Sentinel.Tests.ClaudeCode.Resident;

/// <summary>The state folder of the resident process (#658): the signed profile cache and the pause state, written with
/// write-then-rename, read by a hook without network traffic, with the profile verified as #671 says.</summary>
[Collection("NonParallel")]
public class ResidentProcessStateTests : IDisposable
{
    private const string Org = "acme";
    private const string Repo = "github.com/acme/widgets";
    private static readonly DateTimeOffset Now = new(2026, 11, 23, 10, 0, 0, TimeSpan.Zero);

    private readonly string _dir = ResidentTestSupport.NewDir();
    private readonly ProfileSigningKey _key = ProfileSigningKey.Generate();

    public void Dispose()
    {
        ResidentTestSupport.Delete(_dir);
        GC.SuppressFinalize(this);
    }

    private ResidentState State() => new(ResidentPaths.Prepare(new ResidentSettings(_dir, ResidentSettings.DefaultIdleTimeout, ResidentSettings.DefaultBudget)));

    private PinnedProfileKeys Pinned() => PinnedProfileKeys.Create([_key.PublicKey]);

    private SignedProfile Sign(string module = RegoPolicyTestSupport.Baseline, string org = Org, string repo = Repo, ProfileSigningKey? key = null) =>
        new ProfileSigner(key ?? _key, new FixedTime(Now)).Issue(SignedProfileTests.Sample() with { Organisation = org, Repository = repo, Module = module });

    private static string Input(string command) =>
        PolicyInputSerializer.Serialize(PolicyInputBuilder.Build(
            PolicyClis.ClaudeCode, "Bash", JsonDocument.Parse(JsonSerializer.Serialize(new Dictionary<string, string>(StringComparer.Ordinal) { ["command"] = command })).RootElement,
            "s-1", [], "/work/repo"));

    [Fact]
    public void A_pause_names_a_session_and_a_hook_reads_it_from_disk()
    {
        State().WritePauses([new PausedSession("s-1", "incident review", null)]);

        var hook = State();

        Assert.Equal("incident review", hook.FindPause("s-1", Now)!.Reason);
        Assert.Null(hook.FindPause("s-2", Now));
    }

    [Fact]
    public void A_pause_with_an_end_stops_counting_once_it_has_passed()
    {
        State().WritePauses([new PausedSession("s-1", "lunch", Now.AddMinutes(10))]);

        Assert.NotNull(State().FindPause("s-1", Now));
        Assert.Null(State().FindPause("s-1", Now.AddMinutes(10)));
    }

    [Fact]
    public void Writing_the_pauses_again_replaces_them_and_an_empty_list_lifts_every_pause()
    {
        var state = State();
        state.WritePauses([new PausedSession("s-1", null, null), new PausedSession("s-2", null, null)]);
        state.WritePauses([new PausedSession("s-2", null, null)]);
        Assert.Null(State().FindPause("s-1", Now));
        Assert.NotNull(State().FindPause("s-2", Now));

        state.WritePauses([]);

        Assert.Null(State().FindPause("s-2", Now));
    }

    [Fact]
    public void A_paused_session_is_denied_with_the_reason_and_the_other_sessions_are_not_touched()
    {
        State().WritePauses([new PausedSession("s-1", "incident review", null)]);
        var session = ResidentSession.Open(
            new Dictionary<string, string?>(StringComparer.Ordinal) { [ResidentSettings.EnableVariable] = "on", [ResidentSettings.DirectoryVariable] = _dir }, _ => false)!;
        var allowed = new HookOutput { Decision = HookDecision.Allow };

        var paused = session.ApplyPause(allowed, "s-1", Now);
        var other = session.ApplyPause(allowed, "s-2", Now);

        Assert.Equal(HookDecision.Block, paused.Decision);
        Assert.Contains("incident review", paused.Reason, StringComparison.Ordinal);
        Assert.Equal(DecisionOutcome.Deny, paused.Outcome!.Outcome);
        Assert.Equal([ResidentSession.PauseSource], paused.Outcome.Sources);
        Assert.Equal(OutcomeDecision.InProcess, paused.Outcome.DecidedAt);
        Assert.Same(allowed, other);
    }

    [Fact]
    public async Task A_paused_session_is_denied_by_the_hook_with_nothing_but_the_state_folder()
    {
        State().WritePauses([new PausedSession("cc-9", "incident review", null)]);
        using var env = new EnvironmentScope(
            (ResidentSettings.EnableVariable, "on"), (ResidentSettings.DirectoryVariable, _dir), (LocalPolicy.FolderVariable, null),
            (HookAuditTestSupport.SqliteVar, "off"), ("SENTINEL_HOOK_HEADLESS", null));
        var stderr = new StringWriter();
        var starts = 0;

        var exit = await AI.Sentinel.ClaudeCode.Cli.Program.RunAsync(
            ["pre-tool-use"], new StringReader("""{"session_id":"cc-9","tool_name":"Read","tool_input":{"file_path":"/work/repo/a.cs"}}"""),
            new StringWriter(), stderr, new ExactMatchEmbeddingGenerator(), reviewer: null, policyCompilers: null,
            residentStart: _ => { starts++; return false; });

        Assert.Equal(2, exit);
        Assert.Contains("incident review", stderr.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_file_is_written_whole_and_moved_so_a_reader_never_sees_half_of_it()
    {
        var state = State();
        var small = new[] { new PausedSession("s-1", "a", null) };
        var large = Enumerable.Range(0, 2000).Select(i => new PausedSession($"session-{i}", new string('x', 100), null)).ToArray();
        state.WritePauses(small);
        using var stop = new CancellationTokenSource();
        var writer = Task.Run(() =>
        {
            for (var i = 0; !stop.IsCancellationRequested; i++)
            {
                state.WritePauses(i % 2 == 0 ? large : small);
            }
        }, TestContext.Current.CancellationToken);

        try
        {
            for (var i = 0; i < 1500; i++)
            {
                var seen = State().ReadPauses();
                Assert.True(seen.Count is 1 or 2000, $"a reader saw {seen.Count} pauses");
            }
        }
        finally
        {
            await stop.CancelAsync();
            await writer;
        }

        Assert.DoesNotContain(Directory.GetFiles(ResidentPaths.Directory(new ResidentSettings(_dir, TimeSpan.Zero, TimeSpan.Zero))), f => f.EndsWith(".tmp", StringComparison.Ordinal));
    }

    [Fact]
    public void A_damaged_pause_file_is_an_error_and_a_missing_one_is_not_a_pause()
    {
        var state = State();
        Assert.Empty(state.ReadPauses());
        Assert.Null(state.FindPause("s-1", Now));
        state.WritePauses([new PausedSession("s-1", null, null)]);
        var path = Path.Combine(ResidentPaths.Directory(new ResidentSettings(_dir, TimeSpan.Zero, TimeSpan.Zero)), ResidentState.PauseFile);
        var bytes = File.ReadAllBytes(path);

        File.WriteAllBytes(path, bytes[..(bytes.Length - 3)]);

        Assert.Throws<InvalidDataException>(() => State().ReadPauses());
        Assert.Throws<InvalidDataException>(() => State().FindPause("any-other-session", Now));
        File.WriteAllText(path, "not a state file");
        Assert.Throws<InvalidDataException>(() => State().ReadPauses());
    }

    [Fact]
    public void A_pause_file_that_cannot_be_reached_is_an_error_and_not_a_missing_one()
    {
        if (OperatingSystem.IsWindows() || string.Equals(Environment.UserName, "root", StringComparison.Ordinal))
        {
            Assert.Skip("Needs Unix directory modes and a non-root user.");
            return;
        }

        var state = State();
        state.WritePauses([new PausedSession("s-1", null, null)]);
        var folder = ResidentPaths.Directory(new ResidentSettings(_dir, TimeSpan.Zero, TimeSpan.Zero));
        File.SetUnixFileMode(folder, UnixFileMode.None);
        try
        {
            Assert.Throws<InvalidDataException>(() => state.ReadPauses());
            Assert.Throws<InvalidDataException>(() => state.FindPause("s-1", Now));
        }
        finally
        {
            File.SetUnixFileMode(folder, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
    }

    [Fact]
    public async Task An_unreadable_pause_file_blocks_every_session_with_an_internal_error_and_an_audit_entry()
    {
        State().WritePauses([new PausedSession("cc-9", null, null)]);
        File.WriteAllText(Path.Combine(ResidentPaths.Directory(new ResidentSettings(_dir, TimeSpan.Zero, TimeSpan.Zero)), ResidentState.PauseFile), "damaged");
        var db = Path.Combine(_dir + "-audit", "audit.db");
        Directory.CreateDirectory(Path.GetDirectoryName(db)!);
        try
        {
            using var env = new EnvironmentScope(
                (ResidentSettings.EnableVariable, "on"), (ResidentSettings.DirectoryVariable, _dir), (LocalPolicy.FolderVariable, null),
                (HookAuditTestSupport.SqliteVar, db), ("SENTINEL_HOOK_HEADLESS", null));
            var stderr = new StringWriter();

            var exit = await AI.Sentinel.ClaudeCode.Cli.Program.RunAsync(
                ["pre-tool-use"], new StringReader("""{"session_id":"another","tool_name":"Read","tool_input":{"file_path":"/work/repo/a.cs"}}"""),
                new StringWriter(), stderr, new ExactMatchEmbeddingGenerator(), reviewer: null, policyCompilers: null, residentStart: _ => false);

            Assert.Equal(2, exit);
            Assert.StartsWith(HookInternalError.Prefix, stderr.ToString(), StringComparison.Ordinal);
            Assert.Contains("pause state is unreadable", stderr.ToString(), StringComparison.Ordinal);
            var (entries, _) = await HookAuditTestSupport.ReadAsync(db);
            var entry = Assert.Single(entries);
            Assert.Equal(AI.Sentinel.Authorization.SentinelDenyCodes.InternalError, entry.PolicyCode);
            Assert.Equal("another", entry.SessionId);
        }
        finally
        {
            HookAuditTestSupport.DeleteDir(_dir + "-audit");
        }
    }

    [Fact]
    public void A_profile_that_verifies_is_cached_and_used_offline_until_it_expires()
    {
        var verdict = State().StoreProfile(Sign(), Pinned(), Org, Repo, Now);

        Assert.True(verdict.IsAccepted);
        var hook = State();
        Assert.True(hook.ReadProfile(Pinned(), Org, Repo, Now.AddDays(6))!.IsAccepted);
        var expired = hook.ReadProfile(Pinned(), Org, Repo, Now.AddDays(8))!;
        Assert.False(expired.IsAccepted);
        Assert.Equal(ProfileRejection.Expired, expired.Rejection);
    }

    [Fact]
    public void A_profile_that_fails_its_check_is_not_stored_and_the_last_valid_one_stays()
    {
        var state = State();
        var good = Sign(module: "package sentinel\nimport rego.v1\ndeny contains \"first\" if true\n");
        Assert.True(state.StoreProfile(good, Pinned(), Org, Repo, Now).IsAccepted);
        var forged = Sign(module: "package sentinel\n", key: ProfileSigningKey.Generate());
        var elsewhere = Sign(org: "other");
        var otherRepo = Sign(repo: "github.com/acme/other");

        Assert.Equal(ProfileRejection.UnknownKey, state.StoreProfile(forged, Pinned(), Org, Repo, Now).Rejection);
        Assert.Equal(ProfileRejection.OrganisationMismatch, state.StoreProfile(elsewhere, Pinned(), Org, Repo, Now).Rejection);
        Assert.Equal(ProfileRejection.RepositoryMismatch, state.StoreProfile(otherRepo, Pinned(), Org, Repo, Now).Rejection);

        var kept = State().ReadProfile(Pinned(), Org, Repo, Now)!;
        Assert.True(kept.IsAccepted);
        Assert.Contains("first", kept.Profile!.Module, StringComparison.Ordinal);
    }

    [Fact]
    public void A_cached_profile_that_no_longer_verifies_is_not_used()
    {
        State().StoreProfile(Sign(), Pinned(), Org, Repo, Now);

        Assert.Equal(ProfileRejection.OrganisationMismatch, State().ReadProfile(Pinned(), "other", Repo, Now)!.Rejection);
        Assert.Equal(ProfileRejection.RepositoryMismatch, State().ReadProfile(Pinned(), Org, "github.com/acme/other", Now)!.Rejection);
        Assert.Equal(ProfileRejection.UnknownKey, State().ReadProfile(PinnedProfileKeys.Empty, Org, Repo, Now)!.Rejection);
    }

    [Fact]
    public void A_cached_profile_with_a_changed_byte_does_not_verify()
    {
        var state = State();
        state.StoreProfile(Sign(), Pinned(), Org, Repo, Now);
        var tampered = Sign() with { Signature = Convert.ToBase64String(new byte[64]) };
        var path = Path.Combine(ResidentPaths.Directory(new ResidentSettings(_dir, TimeSpan.Zero, TimeSpan.Zero)), ResidentState.ProfileFile);
        AI.Sentinel.ClaudeCode.Policy.Rego.PolicyCache.Write(path, System.Text.Encoding.UTF8.GetBytes(tampered.ToJson()));

        Assert.Equal(ProfileRejection.BadSignature, State().ReadProfile(Pinned(), Org, Repo, Now)!.Rejection);
    }

    [Fact]
    public void Without_a_cached_profile_there_is_nothing_to_read()
    {
        Assert.Null(State().ReadProfile(Pinned(), Org, Repo, Now));
    }

    [Fact]
    public void While_the_server_is_unreachable_a_call_that_matches_a_deny_rule_of_the_last_valid_profile_is_denied()
    {
        var cache = RegoPolicyTestSupport.SharedCache;
        State().StoreProfile(Sign(), Pinned(), Org, Repo, Now);
        // A newer profile that fails its check does not replace it.
        State().StoreProfile(Sign(module: "package sentinel\n", key: ProfileSigningKey.Generate()), Pinned(), Org, Repo, Now);

        var denied = ProfileDecider.Decide(State(), Pinned(), Org, Repo, Now, Input("rm -rf build"), cache, RegoPolicyTestSupport.Compilers(new ChildProcessCompiler()));
        var untouched = ProfileDecider.Decide(State(), Pinned(), Org, Repo, Now, Input("ls"), cache, RegoPolicyTestSupport.Compilers(new ChildProcessCompiler()));

        Assert.Equal(DecisionOutcome.Deny, denied.Decision!.Outcome);
        Assert.Equal(["recursive delete"], denied.Decision.Reasons);
        Assert.Equal(ProfileRejection.None, denied.Rejection);
        Assert.Equal(DecisionOutcome.Defer, untouched.Decision!.Outcome);
    }

    [Fact]
    public void A_module_folder_whose_file_is_not_the_signed_text_is_never_evaluated()
    {
        var cache = RegoPolicyTestSupport.SharedCache;
        State().StoreProfile(Sign(), Pinned(), Org, Repo, Now);
        ProfileDecider.Decide(State(), Pinned(), Org, Repo, Now, Input("ls"), cache, RegoPolicyTestSupport.Compilers(new ChildProcessCompiler()));
        var file = Directory.GetFiles(Path.Combine(State().Directory, "modules"), "profile.rego", SearchOption.AllDirectories).Single();
        File.WriteAllText(file, "package sentinel\n");

        Assert.Throws<InvalidDataException>(() =>
            ProfileDecider.Decide(State(), Pinned(), Org, Repo, Now, Input("rm -rf build"), cache, RegoPolicyTestSupport.Compilers(new ChildProcessCompiler())));
    }

    [Fact]
    public void A_module_folder_with_a_second_rego_file_is_never_evaluated()
    {
        var cache = RegoPolicyTestSupport.SharedCache;
        State().StoreProfile(Sign(), Pinned(), Org, Repo, Now);
        ProfileDecider.Decide(State(), Pinned(), Org, Repo, Now, Input("ls"), cache, RegoPolicyTestSupport.Compilers(new ChildProcessCompiler()));
        var file = Directory.GetFiles(Path.Combine(State().Directory, "modules"), "profile.rego", SearchOption.AllDirectories).Single();
        File.WriteAllText(Path.Combine(Path.GetDirectoryName(file)!, "extra.rego"), "package sentinel\n\ndeny contains \"unsigned\"\n");

        Assert.Throws<InvalidDataException>(() =>
            ProfileDecider.Decide(State(), Pinned(), Org, Repo, Now, Input("ls"), cache, RegoPolicyTestSupport.Compilers(new ChildProcessCompiler())));
    }

    [Fact]
    public void An_expired_or_missing_profile_gives_no_decision_and_the_reason()
    {
        var cache = RegoPolicyTestSupport.SharedCache;
        var none = ProfileDecider.Decide(State(), Pinned(), Org, Repo, Now, Input("rm -rf build"), cache, RegoPolicyTestSupport.Compilers(new ChildProcessCompiler()));
        State().StoreProfile(Sign(), Pinned(), Org, Repo, Now);
        var expired = ProfileDecider.Decide(State(), Pinned(), Org, Repo, Now.AddDays(30), Input("rm -rf build"), cache, RegoPolicyTestSupport.Compilers(new ChildProcessCompiler()));

        Assert.Null(none.Decision);
        Assert.Null(none.Rejection);
        Assert.Null(expired.Decision);
        Assert.Equal(ProfileRejection.Expired, expired.Rejection);
    }

    private sealed class FixedTime(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
