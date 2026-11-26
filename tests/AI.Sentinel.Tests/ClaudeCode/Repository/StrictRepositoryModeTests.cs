using System.Text.Json;
using AI.Sentinel.ClaudeCode;
using AI.Sentinel.ClaudeCode.Cli;
using AI.Sentinel.ClaudeCode.Policy.Repository;
using AI.Sentinel.ClaudeCode.Resident;
using AI.Sentinel.Tests.ClaudeCode.Resident;
using Xunit;

namespace AI.Sentinel.Tests.ClaudeCode.Repository;

/// <summary>Strict repository mode (#656): a repository no node owns, or a folder outside git, gets the organisation's top-level
/// rules only and sends no events, and the plugin says so at session start. It is on unless it is switched off.</summary>
[Collection("NonParallel")]
public class StrictRepositoryModeTests : IDisposable
{
    private readonly string _root = RepositoryTestSupport.NewDir();
    private readonly string _state = ResidentTestSupport.NewDir();
    private readonly NodeMap _map = new([new("github.com/acme/owned", "node-a")]);

    public void Dispose()
    {
        RepositoryTestSupport.Delete(_root);
        ResidentTestSupport.Delete(_state);
        GC.SuppressFinalize(this);
    }

    private Dictionary<string, string?> Env(string? strict = null)
    {
        var env = new Dictionary<string, string?>(StringComparer.Ordinal)
        {
            [ResidentSettings.EnableVariable] = "on",
            [ResidentSettings.DirectoryVariable] = _state,
        };
        if (strict is not null)
        {
            env[RepositoryScope.StrictVariable] = strict;
        }

        return env;
    }

    private void CacheMap() => ResidentState.Open(ResidentSettings.FromEnvironment(Env())!).WriteNodeMap(_map);

    private static RepositoryTestSupport.FakePolicies Policies(out Func<int> nodeCalls)
    {
        var calls = 0;
        nodeCalls = () => calls;
        return new RepositoryTestSupport.FakePolicies(
            _ => RepositoryTestSupport.Decision(DecisionOutcome.Deny, "organisation forbids it"),
            (_, _) =>
            {
                calls++;
                return RepositoryTestSupport.Decision(DecisionOutcome.Allow, "node allows it");
            });
    }

    [Fact]
    public void Strict_mode_is_on_by_default_and_a_setting_switches_it_off()
    {
        Assert.True(RepositoryScope.StrictFrom(new Dictionary<string, string?>(StringComparer.Ordinal)));
        Assert.True(RepositoryScope.StrictFrom(Env("on")));
        Assert.False(RepositoryScope.StrictFrom(Env("off")));
    }

    [Fact]
    public void A_repository_no_node_owns_gets_the_organisation_rules_only_and_sends_no_events()
    {
        var repo = RepositoryTestSupport.Repo(_root, "stranger", "https://github.com/acme/stranger.git");
        var scope = RepositoryScope.Resolve(repo, _map, strictMode: true);
        var decisions = new RepositoryPolicy(scope, Policies(out var nodeCalls)).Decisions("{}");

        Assert.True(scope.Strict);
        Assert.False(scope.SendsEvents);
        Assert.Equal("github.com/acme/stranger", scope.Repository);
        Assert.Equal("", scope.Node);
        Assert.Equal([RepositoryPolicy.OrganisationSource], Assert.Single(decisions).Sources);
        Assert.Equal(0, nodeCalls());
    }

    [Fact]
    public void A_folder_outside_git_is_strict_too()
    {
        var plain = Path.Combine(_root, "plain");
        Directory.CreateDirectory(plain);

        var scope = RepositoryScope.Resolve(plain, _map, strictMode: true);

        Assert.True(scope.Strict);
        Assert.False(scope.SendsEvents);
        Assert.Equal("", scope.Repository);
        Assert.Contains("not in a git repository", scope.Notice(), StringComparison.Ordinal);
    }

    [Fact]
    public void An_owned_repository_is_not_strict_and_gets_its_node_bundle_too()
    {
        var repo = RepositoryTestSupport.Repo(_root, "owned", "git@github.com:acme/owned.git");
        var scope = RepositoryScope.Resolve(repo, _map, strictMode: true);

        var decisions = new RepositoryPolicy(scope, Policies(out var nodeCalls)).Decisions("{}");

        Assert.False(scope.Strict);
        Assert.True(scope.SendsEvents);
        Assert.Null(scope.Notice());
        Assert.Equal(2, decisions.Count);
        Assert.Equal(1, nodeCalls());
    }

    [Fact]
    public void Switching_strict_mode_off_lets_an_unowned_repository_send_events_without_a_notice()
    {
        var repo = RepositoryTestSupport.Repo(_root, "stranger", "https://github.com/acme/stranger.git");

        var scope = RepositoryScope.Resolve(repo, _map, strictMode: false);

        Assert.False(scope.Strict);
        Assert.True(scope.SendsEvents);
        Assert.Null(scope.Notice());
    }

    [Fact]
    public void A_deny_of_the_organisation_holds_in_strict_mode()
    {
        var plain = Path.Combine(_root, "plain");
        Directory.CreateDirectory(plain);
        var decisions = new RepositoryPolicy(RepositoryScope.Resolve(plain, _map, true), Policies(out _)).Decisions("{}");

        Assert.Equal(DecisionOutcome.Deny, OutcomeDecision.Strictest(decisions).Outcome);
    }

    [Fact]
    public async Task Session_start_tells_the_developer_about_strict_mode()
    {
        CacheMap();
        var repo = RepositoryTestSupport.Repo(_root, "stranger", "https://github.com/acme/stranger.git");
        var stdout = new StringWriter();

        var exit = await SessionStartCommand.RunAsync(Env(), repo, stdout, new StringWriter());

        var json = JsonDocument.Parse(stdout.ToString()).RootElement;
        Assert.Equal(0, exit);
        Assert.Contains("no node owns this repository", json.GetProperty("systemMessage").GetString(), StringComparison.Ordinal);
        Assert.Equal("SessionStart", json.GetProperty("hookSpecificOutput").GetProperty("hookEventName").GetString());
        Assert.Contains("only the organisation's top-level rules", json.GetProperty("hookSpecificOutput").GetProperty("additionalContext").GetString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Session_start_says_nothing_for_an_owned_repository_or_without_a_cached_map_or_with_strict_mode_off()
    {
        var owned = RepositoryTestSupport.Repo(_root, "owned", "https://github.com/acme/owned.git");
        var stranger = RepositoryTestSupport.Repo(_root, "stranger", "https://github.com/acme/stranger.git");

        var noMap = new StringWriter();
        await SessionStartCommand.RunAsync(Env(), stranger, noMap, new StringWriter());
        CacheMap();
        var ownedOut = new StringWriter();
        await SessionStartCommand.RunAsync(Env(), owned, ownedOut, new StringWriter());
        var off = new StringWriter();
        await SessionStartCommand.RunAsync(Env("off"), stranger, off, new StringWriter());

        Assert.Equal("", noMap.ToString());
        Assert.Equal("", ownedOut.ToString());
        Assert.Equal("", off.ToString());
    }

    [Fact]
    public async Task A_broken_map_is_reported_by_session_start()
    {
        var plain = Path.Combine(_root, "plain");
        Directory.CreateDirectory(plain);
        CacheMap();
        File.WriteAllText(Path.Combine(ResidentPaths.Directory(ResidentSettings.FromEnvironment(Env())!), ResidentState.NodesFile), "garbage");
        var stderr = new StringWriter();

        var exit = await SessionStartCommand.RunAsync(Env(), plain, new StringWriter(), stderr);

        Assert.Equal(1, exit);
        Assert.Contains("node map is unreadable", stderr.ToString(), StringComparison.Ordinal);
        Assert.True(SessionStartCommand.Matches(["session-start"]));
    }
}
