using System.Text.Json;
using AI.Sentinel.ClaudeCode;
using AI.Sentinel.ClaudeCode.Policy;
using AI.Sentinel.ClaudeCode.Policy.Rego;
using AI.Sentinel.ClaudeCode.Policy.Repository;
using AI.Sentinel.ClaudeCode.Resident;
using AI.Sentinel.Profiles;
using AI.Sentinel.Tests.ClaudeCode.Policy;
using AI.Sentinel.Tests.ClaudeCode.Resident;
using AI.Sentinel.Tests.Profiles;
using Xunit;

namespace AI.Sentinel.Tests.ClaudeCode.Repository;

/// <summary>The policy of a call is the policy of the node that owns the repository of the working directory (#656): the repository
/// is read from the git files, the node from the cached map, and nothing is fetched.</summary>
[Collection("NonParallel")]
public class RepositoryNodePolicyTests : IDisposable
{
    private static readonly HookOutput Allowed = new() { Decision = HookDecision.Allow };
    private static readonly DateTimeOffset Now = new(2026, 11, 23, 10, 0, 0, TimeSpan.Zero);

    private readonly string _root = RepositoryTestSupport.NewDir();
    private readonly string _state = ResidentTestSupport.NewDir();

    public void Dispose()
    {
        RepositoryTestSupport.Delete(_root);
        ResidentTestSupport.Delete(_state);
        GC.SuppressFinalize(this);
    }

    private static JsonElement Json(string json) => JsonDocument.Parse(json).RootElement;

    [Theory]
    [InlineData("https://github.com/Acme/Widgets.git", "github.com/acme/widgets")]
    [InlineData("git@github.com:Acme/Widgets.git", "github.com/acme/widgets")]
    [InlineData("ssh://git@github.com:22/acme/widgets", "github.com/acme/widgets")]
    [InlineData("https://GitHub.com/acme/widgets/", "github.com/acme/widgets")]
    [InlineData("https://user:s3cr3t-token@github.com/acme/widgets.git", "github.com/acme/widgets")]
    [InlineData("https://x-access-token:ghp_abc@github.com/acme/widgets", "github.com/acme/widgets")]
    [InlineData("github.com/acme/widgets", null)]
    [InlineData("/srv/git/widgets.git", null)]
    [InlineData("file:///srv/git/widgets.git", null)]
    [InlineData("", null)]
    public void A_remote_url_is_normalised_to_one_name_without_credentials(string url, string? expected)
    {
        Assert.Equal(expected, RepositoryUrl.Normalize(url));
    }

    [Theory]
    [InlineData("https://[2001:db8::1]/acme/widgets", "[2001:db8::1]/acme/widgets")]
    [InlineData("https://[2001:db8::1]:8443/acme/widgets.git", "[2001:db8::1]/acme/widgets")]
    [InlineData("ssh://git@[2001:db8::1]:22/acme/widgets", "[2001:db8::1]/acme/widgets")]
    [InlineData("git@[2001:db8::1]:acme/widgets.git", "[2001:db8::1]/acme/widgets")]
    [InlineData("[2001:db8::1]/acme/widgets", "[2001:db8::1]/acme/widgets")]
    public void A_bracketed_ipv6_host_keeps_its_literal_and_loses_its_port(string url, string expected)
    {
        Assert.Equal(expected, RepositoryUrl.Normalize(url));
    }

    [Fact]
    public void A_canonical_ipv6_key_survives_the_cache_file()
    {
        var map = NodeMap.FromJson(new NodeMap([new("https://[2001:db8::1]/acme/widgets", "node-a")]).ToJson());

        Assert.Equal("node-a", map.NodeFor("[2001:db8::1]/acme/widgets"));
    }

    [Fact]
    public void A_key_that_was_stored_is_restored_as_it_is_even_when_it_ends_in_two_git_suffixes()
    {
        var map = NodeMap.FromJson(new NodeMap([new("https://[2001:db8::1]/acme/widgets.git.git", "node-a")]).ToJson());

        Assert.Equal("node-a", map.NodeFor("[2001:db8::1]/acme/widgets.git"));
    }

    [Theory]
    [InlineData("[remote \"origin\"] url = https://github.com/acme/widgets.git")]
    [InlineData("[remote \"origin\"]\turl = https://github.com/acme/widgets.git # primary")]
    public void An_assignment_on_the_line_of_its_section_header_is_read(string text)
    {
        var repo = Path.Combine(_root, "oneline");
        Directory.CreateDirectory(Path.Combine(repo, ".git"));
        File.WriteAllText(Path.Combine(repo, ".git", "config"), text + "\n");

        Assert.Equal("https://github.com/acme/widgets.git", GitRemote.UrlOf(repo));
    }

    [Theory]
    [InlineData("https://github.com/acme/widgets.git # primary")]
    [InlineData("https://github.com/acme/widgets.git ; primary")]
    [InlineData("https://github.com/acme/widgets.git#primary")]
    [InlineData("\"https://github.com/acme/widgets.git\" # primary")]
    public void A_comment_after_the_remote_url_is_not_part_of_it(string value)
    {
        var repo = Path.Combine(_root, "commented");
        Directory.CreateDirectory(Path.Combine(repo, ".git"));
        File.WriteAllText(Path.Combine(repo, ".git", "config"), "[remote \"origin\"]\n\turl = " + value + "\n");

        Assert.Equal("https://github.com/acme/widgets.git", GitRemote.UrlOf(repo));
    }

    [Fact]
    public void A_comment_character_inside_a_quoted_url_is_kept()
    {
        var repo = Path.Combine(_root, "quoted");
        Directory.CreateDirectory(Path.Combine(repo, ".git"));
        File.WriteAllText(Path.Combine(repo, ".git", "config"), "[remote \"origin\"]\n\turl = \"https://host/a#b\" # note\n");

        Assert.Equal("https://host/a#b", GitRemote.UrlOf(repo));
    }

    [Fact]
    public void A_remote_defined_in_an_included_file_is_read_in_place_and_a_loop_ends()
    {
        var repo = Path.Combine(_root, "included");
        var git = Path.Combine(repo, ".git");
        Directory.CreateDirectory(Path.Combine(git, "conf"));
        File.WriteAllText(Path.Combine(git, "config"), "[core]\n\tbare = false\n[include]\n\tpath = conf/remotes.conf\n");
        File.WriteAllText(Path.Combine(git, "conf", "remotes.conf"), "[remote \"origin\"]\n\turl = https://github.com/acme/widgets.git\n[include]\n\tpath = remotes.conf\n");

        Assert.Equal("https://github.com/acme/widgets.git", GitRemote.UrlOf(repo));
    }

    [Fact]
    public void A_remote_in_the_config_follows_an_include_in_configuration_order_and_a_missing_include_is_skipped()
    {
        var repo = Path.Combine(_root, "ordered");
        var git = Path.Combine(repo, ".git");
        Directory.CreateDirectory(git);
        File.WriteAllText(Path.Combine(git, "config"), "[include]\n\tpath = missing.conf\n\tpath = other.conf\n[remote \"origin\"]\n\turl = https://github.com/acme/own.git\n");
        File.WriteAllText(Path.Combine(git, "other.conf"), "[remote \"origin\"]\n\turl = https://github.com/acme/included.git\n");

        Assert.Equal("https://github.com/acme/included.git", GitRemote.UrlOf(repo));
    }

    [Fact]
    public void The_ssh_and_the_https_form_of_one_remote_are_the_same_repository()
    {
        Assert.Equal(RepositoryUrl.Normalize("git@github.com:acme/widgets.git"), RepositoryUrl.Normalize("https://github.com/ACME/widgets"));
    }

    [Fact]
    public void The_remote_is_read_from_the_git_config_of_the_working_directory_and_of_a_folder_below_it()
    {
        var repo = RepositoryTestSupport.Repo(_root, "widgets", "git@github.com:acme/widgets.git");
        var below = Path.Combine(repo, "src", "deep");
        Directory.CreateDirectory(below);

        Assert.Equal("git@github.com:acme/widgets.git", GitRemote.UrlOf(repo));
        Assert.Equal("git@github.com:acme/widgets.git", GitRemote.UrlOf(below));
    }

    [Fact]
    public void Origin_wins_over_another_remote_and_a_repository_with_one_other_remote_uses_it()
    {
        var repo = Path.Combine(_root, "fork");
        Directory.CreateDirectory(Path.Combine(repo, ".git"));
        File.WriteAllText(
            Path.Combine(repo, ".git", "config"),
            RepositoryTestSupport.Config("https://github.com/upstream/widgets", "upstream") + RepositoryTestSupport.Config("https://github.com/me/widgets", "origin"));
        var only = Path.Combine(_root, "only");
        Directory.CreateDirectory(Path.Combine(only, ".git"));
        File.WriteAllText(Path.Combine(only, ".git", "config"), RepositoryTestSupport.Config("https://github.com/acme/widgets", "upstream"));

        Assert.Equal("https://github.com/me/widgets", GitRemote.UrlOf(repo));
        Assert.Equal("https://github.com/acme/widgets", GitRemote.UrlOf(only));
    }

    [Fact]
    public void A_worktree_reads_the_config_of_the_repository_it_belongs_to()
    {
        var main = RepositoryTestSupport.Repo(_root, "main", "https://github.com/acme/widgets.git");
        var gitDir = Path.Combine(main, ".git", "worktrees", "feature");
        Directory.CreateDirectory(gitDir);
        File.WriteAllText(Path.Combine(gitDir, "commondir"), "../..\n");
        var tree = Path.Combine(_root, "feature-tree");
        Directory.CreateDirectory(tree);
        File.WriteAllText(Path.Combine(tree, ".git"), $"gitdir: {gitDir}\n");

        Assert.Equal("https://github.com/acme/widgets.git", GitRemote.UrlOf(tree));
    }

    [Fact]
    public void A_submodule_reads_its_own_remote_through_a_relative_gitdir()
    {
        var super = RepositoryTestSupport.Repo(_root, "super", "https://github.com/acme/super.git");
        var modules = Path.Combine(super, ".git", "modules", "lib");
        Directory.CreateDirectory(modules);
        File.WriteAllText(Path.Combine(modules, "config"), RepositoryTestSupport.Config("https://github.com/acme/lib.git"));
        var sub = Path.Combine(super, "lib");
        Directory.CreateDirectory(sub);
        File.WriteAllText(Path.Combine(sub, ".git"), "gitdir: ../.git/modules/lib\n");

        Assert.Equal("https://github.com/acme/lib.git", GitRemote.UrlOf(sub));
    }

    [Fact]
    public void A_folder_outside_git_and_a_repository_without_a_remote_have_no_url()
    {
        var plain = Path.Combine(_root, "plain");
        Directory.CreateDirectory(plain);
        var bare = Path.Combine(_root, "noremote");
        Directory.CreateDirectory(Path.Combine(bare, ".git"));
        File.WriteAllText(Path.Combine(bare, ".git", "config"), "[core]\n\tbare = false\n");

        Assert.Null(GitRemote.UrlOf(plain));
        Assert.Null(GitRemote.UrlOf(bare));
    }

    [Fact]
    public void The_policy_input_carries_the_repository_and_the_node_and_never_a_credential()
    {
        var repo = RepositoryTestSupport.Repo(_root, "widgets", "https://deploy:hunter2@github.com/Acme/Widgets.git");
        var scope = RepositoryScope.Resolve(repo, new NodeMap([new("git@github.com:acme/widgets.git", "node-a")]), strictMode: true);

        var input = PolicyInputBuilder.Build(PolicyClis.ClaudeCode, "Bash", Json("""{"command":"ls"}"""), "s-1", [], repo, scope.Repository, scope.Node);
        var json = PolicyInputSerializer.Serialize(input);

        var root = JsonDocument.Parse(json).RootElement;
        Assert.Equal("github.com/acme/widgets", root.GetProperty("repository").GetString());
        Assert.Equal("node-a", root.GetProperty("node").GetString());
        Assert.DoesNotContain("hunter2", json, StringComparison.Ordinal);
        Assert.DoesNotContain("deploy", json, StringComparison.Ordinal);
    }

    [Fact]
    public void Two_repositories_owned_by_different_nodes_get_different_outcomes_for_the_same_call()
    {
        var a = RepositoryTestSupport.Repo(_root, "a", "https://github.com/acme/alpha.git");
        var b = RepositoryTestSupport.Repo(_root, "b", "https://github.com/acme/beta.git");
        var map = new NodeMap([new("github.com/acme/alpha", "node-a"), new("github.com/acme/beta", "node-b")]);
        var policies = new RepositoryTestSupport.FakePolicies(
            _ => null,
            (repository, _) => repository.EndsWith("alpha", StringComparison.Ordinal)
                ? RepositoryTestSupport.Decision(DecisionOutcome.Deny, "alpha forbids it")
                : RepositoryTestSupport.Decision(DecisionOutcome.Allow, "beta allows it"));

        var inA = new RepositoryPolicy(RepositoryScope.Resolve(a, map, true), policies).Decisions("{}");
        var inB = new RepositoryPolicy(RepositoryScope.Resolve(b, map, true), policies).Decisions("{}");

        Assert.Equal(DecisionOutcome.Deny, Assert.Single(inA).Outcome);
        Assert.Equal(["node:node-a"], inA[0].Sources);
        Assert.Equal(DecisionOutcome.Allow, Assert.Single(inB).Outcome);
        Assert.Equal(["node:node-b"], inB[0].Sources);
    }

    [Fact]
    public void A_deny_of_the_organisation_holds_in_a_repository_whose_node_bundle_allows_the_call()
    {
        var repo = RepositoryTestSupport.Repo(_root, "a", "https://github.com/acme/alpha.git");
        var policies = new RepositoryTestSupport.FakePolicies(
            _ => RepositoryTestSupport.Decision(DecisionOutcome.Deny, "organisation forbids it"),
            (_, _) => RepositoryTestSupport.Decision(DecisionOutcome.Allow, "node allows it"));
        var scope = RepositoryScope.Resolve(repo, new NodeMap([new("github.com/acme/alpha", "node-a")]), true);

        var combined = OutcomeDecision.Strictest(new RepositoryPolicy(scope, policies).Decisions("{}"));

        Assert.Equal(DecisionOutcome.Deny, combined.Outcome);
        Assert.Equal("organisation forbids it", combined.Reason);
    }

    [Fact]
    public void Signed_profiles_in_the_state_folder_give_the_organisation_deny_over_the_node_allow()
    {
        var key = ProfileSigningKey.Generate();
        var pinned = PinnedProfileKeys.Create([key.PublicKey]);
        var signer = new ProfileSigner(key, new FixedClock(Now));
        var state = new ResidentState(ResidentPaths.Prepare(new ResidentSettings(_state, ResidentSettings.DefaultIdleTimeout, ResidentSettings.DefaultBudget)));
        const string Repo = "github.com/acme/alpha";
        const string NodeAllows = "package sentinel\n\nimport rego.v1\n\nallow contains \"node allows\" if input.kind == \"shell\"\n";
        state.StoreProfile(signer.Issue(SignedProfileTests.Sample() with { Organisation = "acme", Repository = CachedNodePolicies.OrganisationRepository, Module = RegoPolicyTestSupport.Baseline }),
            pinned, "acme", CachedNodePolicies.OrganisationRepository, Now, CachedNodePolicies.SlotOf(CachedNodePolicies.OrganisationRepository));
        state.StoreProfile(signer.Issue(SignedProfileTests.Sample() with { Organisation = "acme", Repository = Repo, Module = NodeAllows }),
            pinned, "acme", Repo, Now, CachedNodePolicies.SlotOf(Repo));
        var policies = new CachedNodePolicies(state, pinned, "acme", () => Now, RegoPolicyTestSupport.SharedCache, RegoPolicyTestSupport.Compilers(new ChildProcessCompiler()));
        var scope = new RepositoryScope(Repo, "node-a", StrictMode: true);
        var input = PolicyInputSerializer.Serialize(PolicyInputBuilder.Build(
            PolicyClis.ClaudeCode, "Bash", Json("""{"command":"rm -rf build"}"""), "s-1", [], "/work/repo", scope.Repository, scope.Node));

        var combined = OutcomeDecision.Strictest(new RepositoryPolicy(scope, policies).Decisions(input));

        Assert.Equal(DecisionOutcome.Deny, combined.Outcome);
        Assert.Contains("recursive delete", combined.Reason, StringComparison.Ordinal);
        Assert.Contains(RepositoryPolicy.OrganisationSource, combined.Sources, StringComparer.Ordinal);
    }

    [Fact]
    public void With_a_server_and_a_local_folder_both_are_evaluated_and_the_strictest_wins_and_the_folder_cannot_loosen_the_profile()
    {
        var repo = RepositoryTestSupport.Repo(_root, "a", "https://github.com/acme/alpha.git");
        var folder = RegoPolicyTestSupport.StandardFolder();
        try
        {
            using var local = LocalPolicy.Load(folder, RegoPolicyTestSupport.Env(), repo, RegoPolicyTestSupport.Compilers(new ChildProcessCompiler()));
            var scope = RepositoryScope.Resolve(repo, new NodeMap([new("github.com/acme/alpha", "node-a")]), true);
            // The profile denies curl; the local folder denies rm -rf and asks for a fetch; the profile also tries to allow rm.
            local.RepositoryPolicy = new RepositoryPolicy(scope, new RepositoryTestSupport.FakePolicies(
                _ => null,
                (_, input) => input.Contains("curl", StringComparison.Ordinal)
                    ? RepositoryTestSupport.Decision(DecisionOutcome.Deny, "profile denies curl")
                    : RepositoryTestSupport.Decision(DecisionOutcome.Allow, "profile allows the rest")));

            var curl = local.Decide(Allowed, PolicyClis.ClaudeCode, "Bash", Json("""{"command":"curl example.com"}"""), "s-1");
            var rm = local.Decide(Allowed, PolicyClis.ClaudeCode, "Bash", Json("""{"command":"rm -rf build"}"""), "s-1");
            var ls = local.Decide(Allowed, PolicyClis.ClaudeCode, "Bash", Json("""{"command":"ls"}"""), "s-1");

            Assert.Equal(HookDecision.Block, curl.Decision);
            Assert.Contains("profile denies curl", curl.Reason, StringComparison.Ordinal);
            Assert.Equal(HookDecision.Block, rm.Decision);
            Assert.Contains("recursive delete", rm.Reason, StringComparison.Ordinal);
            Assert.Equal(DecisionOutcome.Allow, ls.Outcome!.Outcome);
        }
        finally
        {
            RegoPolicyTestSupport.Delete(folder);
        }
    }

    [Fact]
    public void The_input_of_the_local_folder_names_the_repository_and_the_node()
    {
        var repo = RepositoryTestSupport.Repo(_root, "a", "git@github.com:Acme/Alpha.git");
        var folder = RegoPolicyTestSupport.Folder((
            "p/p.rego",
            "package sentinel\n\nimport rego.v1\n\ndeny contains \"wrong node\" if input.node != \"node-a\"\n\ndeny contains \"wrong repository\" if input.repository != \"github.com/acme/alpha\"\n"));
        try
        {
            using var local = LocalPolicy.Load(folder, RegoPolicyTestSupport.Env(), repo, RegoPolicyTestSupport.Compilers(new ChildProcessCompiler()));
            var scope = RepositoryScope.Resolve(repo, new NodeMap([new("github.com/acme/alpha", "node-a")]), true);
            var without = local.Decide(Allowed, PolicyClis.ClaudeCode, "Bash", Json("""{"command":"ls"}"""), "s-1");
            local.RepositoryPolicy = new RepositoryPolicy(scope, NoNodePolicies.Instance);

            var with = local.Decide(Allowed, PolicyClis.ClaudeCode, "Bash", Json("""{"command":"ls"}"""), "s-1");

            Assert.Equal(HookDecision.Block, without.Decision);
            Assert.NotEqual(HookDecision.Block, with.Decision);
        }
        finally
        {
            RegoPolicyTestSupport.Delete(folder);
        }
    }

    [Fact]
    public void The_decision_reads_the_state_folder_only_and_a_map_that_cannot_be_read_blocks()
    {
        var repo = RepositoryTestSupport.Repo(_root, "a", "https://github.com/acme/alpha.git");
        var env = new Dictionary<string, string?>(StringComparer.Ordinal) { [ResidentSettings.EnableVariable] = "on", [ResidentSettings.DirectoryVariable] = _state };
        Assert.Null(RepositoryPolicy.Open(env, repo));

        ResidentState.Open(ResidentSettings.FromEnvironment(env)!).WriteNodeMap(new NodeMap([new("github.com/acme/alpha", "node-a")]));
        var opened = RepositoryPolicy.Open(env, repo)!;

        Assert.Equal("node-a", opened.Scope.Node);
        Assert.Equal("github.com/acme/alpha", opened.Scope.Repository);
        File.WriteAllText(Path.Combine(ResidentPaths.Directory(ResidentSettings.FromEnvironment(env)!), ResidentState.NodesFile), "not a map");
        Assert.Throws<InvalidDataException>(() => RepositoryPolicy.Open(env, repo));
    }

    [Fact]
    public void A_node_map_path_that_is_a_directory_blocks_instead_of_reading_as_no_map()
    {
        var repo = RepositoryTestSupport.Repo(_root, "a", "https://github.com/acme/alpha.git");
        var env = new Dictionary<string, string?>(StringComparer.Ordinal) { [ResidentSettings.EnableVariable] = "on", [ResidentSettings.DirectoryVariable] = _state };
        var settings = ResidentSettings.FromEnvironment(env)!;
        ResidentState.Open(settings);
        Directory.CreateDirectory(Path.Combine(ResidentPaths.Directory(settings), ResidentState.NodesFile));

        Assert.Throws<InvalidDataException>(() => RepositoryPolicy.Open(env, repo));
    }

    [Fact]
    public void Without_a_policy_folder_the_repository_policy_alone_decides_the_call()
    {
        var repo = RepositoryTestSupport.Repo(_root, "a", "https://github.com/acme/alpha.git");
        var stranger = RepositoryTestSupport.Repo(_root, "stranger", "https://github.com/acme/stranger.git");
        var env = new Dictionary<string, string?>(StringComparer.Ordinal) { [ResidentSettings.EnableVariable] = "on", [ResidentSettings.DirectoryVariable] = _state };
        Assert.Null(LocalPolicy.LoadRepositoryOnly(env, repo));

        ResidentState.Open(ResidentSettings.FromEnvironment(env)!).WriteNodeMap(new NodeMap([new("github.com/acme/alpha", "node-a")]));
        using var owned = LocalPolicy.LoadRepositoryOnly(env, repo)!;
        using var strict = LocalPolicy.LoadRepositoryOnly(env, stranger)!;
        var policies = new RepositoryTestSupport.FakePolicies(
            _ => RepositoryTestSupport.Decision(DecisionOutcome.Deny, "organisation forbids it"),
            (_, _) => RepositoryTestSupport.Decision(DecisionOutcome.Allow, "node allows it"));
        owned.RepositoryPolicy = new RepositoryPolicy(owned.RepositoryPolicy!.Scope, policies);
        strict.RepositoryPolicy = new RepositoryPolicy(strict.RepositoryPolicy!.Scope, policies);

        var ownedDecision = owned.Decide(Allowed, PolicyClis.ClaudeCode, "Bash", Json("""{"command":"ls"}"""), "s-1");
        var strictDecision = strict.Decide(Allowed, PolicyClis.ClaudeCode, "Bash", Json("""{"command":"ls"}"""), "s-1");

        Assert.Equal("node-a", owned.RepositoryPolicy.Scope.Node);
        Assert.True(strict.RepositoryPolicy.Scope.Strict);
        Assert.Equal(HookDecision.Block, ownedDecision.Decision);
        Assert.Equal(HookDecision.Block, strictDecision.Decision);
        Assert.Equal(SeverityActions.None, owned.Severities());
    }

    [Fact]
    public void Without_a_policy_folder_a_node_map_that_cannot_be_read_blocks()
    {
        var env = new Dictionary<string, string?>(StringComparer.Ordinal) { [ResidentSettings.EnableVariable] = "on", [ResidentSettings.DirectoryVariable] = _state };
        var settings = ResidentSettings.FromEnvironment(env)!;
        ResidentState.Open(settings).WriteNodeMap(new NodeMap([new("github.com/acme/alpha", "node-a")]));
        File.WriteAllText(Path.Combine(ResidentPaths.Directory(settings), ResidentState.NodesFile), "garbage");

        Assert.Throws<InvalidDataException>(() => LocalPolicy.LoadRepositoryOnly(env, _root));
    }

    [Fact]
    public void Without_a_resident_process_setting_nothing_is_resolved()
    {
        var env = new Dictionary<string, string?>(StringComparer.Ordinal);

        Assert.Null(RepositoryPolicy.Open(env, _root));
    }

    private sealed class FixedClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
