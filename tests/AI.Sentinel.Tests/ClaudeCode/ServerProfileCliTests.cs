using System.Security.Cryptography;
using System.Text;
using AI.Sentinel.ClaudeCode.Policy.Repository;
using AI.Sentinel.ClaudeCode.Resident;
using AI.Sentinel.ClaudeCode.SignIn;
using AI.Sentinel.Profiles;
using AI.Sentinel.Tests.ClaudeCode.Policy;
using AI.Sentinel.Tests.ClaudeCode.Repository;
using AI.Sentinel.Tests.ClaudeCode.Resident;
using AI.Sentinel.Tests.Helpers;
using AI.Sentinel.Tests.Profiles;
using Xunit;
using ClaudeProgram = AI.Sentinel.ClaudeCode.Cli.Program;
using CopilotProgram = AI.Sentinel.Copilot.Cli.Program;

namespace AI.Sentinel.Tests.ClaudeCode;

/// <summary>The signed profiles of the server decide a call in both hook CLIs (#729): the organisation's top-level rules everywhere,
/// a node's bundle in the repositories it owns, and the fail mode when the profile is missing or expired. Every test runs a hook end to
/// end, as Claude Code and Copilot start it, in a repository folder with a signed-in state folder next to it.</summary>
[Collection("NonParallel")]
public class ServerProfileCliTests : IDisposable
{
    private const string Organisation = "acme";
    private const string Alpha = "github.com/acme/alpha";
    private const string Beta = "github.com/acme/beta";

    private const string AlphaBundle = """
        package sentinel

        import rego.v1

        deny contains "node-a does not deploy from a developer machine" if {
        	input.kind == "shell"
        	some c in input.details.shell.commands
        	c.name == "make"
        	"deploy" in c.args
        }
        """;

    private const string BetaBundle = """
        package sentinel

        import rego.v1

        guidance contains "node-b has nothing against this" if input.kind == "shell"
        """;

    // Redefines the decision rule of the host, so OPA reports a conflict on every evaluation: it loads, and fails while it runs.
    private const string Clash = "package sentinel\nimport rego.v1\ndecision := {\"outcome\": \"allow\", \"reasons\": [\"mine\"]}\n";

    private static readonly string[] Variables =
    [
        SignInSettings.ServerVariable, SignInSettings.IssuerVariable, SignInSettings.ClientIdVariable, ResidentSettings.DirectoryVariable,
        ResidentSettings.EnableVariable, ResidentSettings.BudgetVariable, RepositoryScope.StrictVariable, "SENTINEL_HOOK_POLICY_DIR",
        HookAuditTestSupport.SqliteVar, "SENTINEL_APPROVAL_CONFIG",
    ];

    private readonly Dictionary<string, string?> _saved = Variables.ToDictionary(v => v, Environment.GetEnvironmentVariable, StringComparer.Ordinal);
    private readonly string _savedDirectory = Directory.GetCurrentDirectory();
    private readonly string _root = RepositoryTestSupport.NewDir();
    private readonly string _stateRoot = ResidentTestSupport.NewDir();
    private readonly ProfileSigningKey _key = ProfileSigningKey.Generate();
    private readonly ResidentState _state;
    private readonly string _alpha;
    private readonly string _beta;
    private readonly string _stranger;

    public ServerProfileCliTests()
    {
        foreach (var variable in Variables)
        {
            Environment.SetEnvironmentVariable(variable, null);
        }

        Environment.SetEnvironmentVariable(HookAuditTestSupport.SqliteVar, "off");
        Environment.SetEnvironmentVariable(ResidentSettings.DirectoryVariable, _stateRoot);
        _state = new ResidentState(ResidentPaths.Prepare(Settings(_stateRoot)));
        _alpha = RepositoryTestSupport.Repo(_root, "alpha", "https://github.com/Acme/Alpha.git");
        _beta = RepositoryTestSupport.Repo(_root, "beta", "git@github.com:acme/beta.git");
        _stranger = RepositoryTestSupport.Repo(_root, "stranger", "https://github.com/acme/stranger.git");
    }

    public void Dispose()
    {
        Directory.SetCurrentDirectory(_savedDirectory);
        foreach (var (variable, value) in _saved)
        {
            Environment.SetEnvironmentVariable(variable, value);
        }

        RepositoryTestSupport.Delete(_root);
        ResidentTestSupport.Delete(_stateRoot);
        GC.SuppressFinalize(this);
    }

    public static TheoryData<string> Clis => new() { "claude", "copilot" };

    private static ResidentSettings Settings(string directory) => new(directory, ResidentSettings.DefaultIdleTimeout, ResidentSettings.DefaultBudget);

    private static void ServerConfigured()
    {
        Environment.SetEnvironmentVariable(SignInSettings.ServerVariable, "https://sentinel.example.com");
        Environment.SetEnvironmentVariable(SignInSettings.IssuerVariable, "https://login.example.com");
        Environment.SetEnvironmentVariable(SignInSettings.ClientIdVariable, "plugin");
    }

    private PinnedProfileKeys Pinned => PinnedProfileKeys.Create([_key.PublicKey]);

    /// <summary>A PC that signed in and whose resident process fetched the node map and the profiles of the organisation, alpha and beta.</summary>
    private void SignedIn(string? organisationModule = RegoPolicyTestSupport.Baseline, string? alphaModule = AlphaBundle, string failMode = ProfileFailModes.Closed)
    {
        ServerConfigured();
        _state.WritePinnedKeys(Organisation, Pinned);
        _state.WriteNodeMap(new NodeMap([new(Alpha, "node-a"), new(Beta, "node-b")]));
        if (organisationModule is not null)
        {
            Store(CachedNodePolicies.OrganisationRepository, organisationModule, failMode);
        }

        if (alphaModule is not null)
        {
            Store(Alpha, alphaModule, failMode);
        }

        Store(Beta, BetaBundle, failMode);
    }

    private void Store(string repository, string module, string failMode = ProfileFailModes.Closed, DateTimeOffset? issuedAt = null)
    {
        var at = issuedAt ?? DateTimeOffset.UtcNow;
        var signer = new ProfileSigner(_key, new FixedClock(at));
        var profile = SignedProfileTests.Sample() with
        {
            Organisation = Organisation,
            Repository = repository,
            Node = string.Equals(repository, CachedNodePolicies.OrganisationRepository, StringComparison.Ordinal) ? "acme" : "node",
            Module = module,
            ModuleHash = "sha256:" + Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(module))),
            FailMode = failMode,
        };
        Assert.True(_state.StoreProfile(signer.Issue(profile), Pinned, Organisation, repository, at, CachedNodePolicies.SlotOf(repository)).IsAccepted);
    }

    private static async Task<(string Outcome, string Text)> RunAsync(string cli, string folder, string command)
    {
        Directory.SetCurrentDirectory(folder);
        var stdout = new StringWriter();
        var stderr = new StringWriter();
        var compilers = RegoPolicyTestSupport.Compilers(new ChildProcessCompiler());
        if (string.Equals(cli, "claude", StringComparison.Ordinal))
        {
            var json = $$$"""{"session_id":"sp","tool_name":"Bash","tool_input":{"command":"{{{command}}}"}}""";
            var exit = await ClaudeProgram.RunAsync(
                ["pre-tool-use"], new StringReader(json), stdout, stderr, new ExactMatchEmbeddingGenerator(), reviewer: null, compilers,
                residentStart: _ => false);
            var text = stdout + "\n" + stderr;
            var outcome = exit == 2 || text.Contains("\"permissionDecision\":\"deny\"", StringComparison.Ordinal) ? "deny"
                : text.Contains("\"permissionDecision\":\"ask\"", StringComparison.Ordinal) ? "ask"
                : exit == 0 ? "allow" : $"exit {exit}";
            return (outcome, text);
        }

        var copilot = $$$"""{"sessionId":"sp","toolName":"bash","toolArgs":{"command":"{{{command}}}"}}""";
        var code = await CopilotProgram.RunAsync(
            ["pre-tool-use"], new StringReader(copilot), stdout, stderr, new ExactMatchEmbeddingGenerator(), reviewer: null, compilers,
            residentStart: _ => false);
        var all = stdout + "\n" + stderr;
        return (all.Contains("\"decision\":\"Block\"", StringComparison.Ordinal) ? "deny" : code == 0 ? "allow" : $"exit {code}", all);
    }

    [Theory]
    [MemberData(nameof(Clis))]
    public async Task A_deny_rule_of_the_organisation_blocks_the_call(string cli)
    {
        SignedIn();

        var (outcome, text) = await RunAsync(cli, _beta, "rm -rf build");

        Assert.Equal("deny", outcome);
        Assert.Contains("recursive delete", text, StringComparison.Ordinal);
    }

    [Theory]
    [MemberData(nameof(Clis))]
    public async Task A_node_bundle_applies_in_the_repository_its_node_owns_and_nowhere_else(string cli)
    {
        SignedIn();

        var (inAlpha, alphaText) = await RunAsync(cli, _alpha, "make deploy");
        var (inBeta, _) = await RunAsync(cli, _beta, "make deploy");

        Assert.Equal("deny", inAlpha);
        Assert.Contains("node-a does not deploy from a developer machine", alphaText, StringComparison.Ordinal);
        Assert.Equal("allow", inBeta);
    }

    [Theory]
    [MemberData(nameof(Clis))]
    public async Task In_strict_mode_a_repository_no_node_owns_gets_the_organisation_rules_only(string cli)
    {
        SignedIn();
        // A profile cached for the unowned repository is never consulted: strict mode gives the organisation's rules only.
        Store("github.com/acme/stranger", AlphaBundle);

        var (delete, deleteText) = await RunAsync(cli, _stranger, "rm -rf build");
        var (deploy, _) = await RunAsync(cli, _stranger, "make deploy");

        Assert.Equal("deny", delete);
        Assert.Contains("recursive delete", deleteText, StringComparison.Ordinal);
        Assert.Equal("allow", deploy);
    }

    [Theory]
    [InlineData("claude", "organisation", ProfileFailModes.Closed, "deny")]
    [InlineData("claude", "organisation", ProfileFailModes.Ask, "ask")]
    [InlineData("claude", "node", ProfileFailModes.Closed, "deny")]
    [InlineData("claude", "node", ProfileFailModes.Ask, "ask")]
    [InlineData("copilot", "organisation", ProfileFailModes.Closed, "deny")]
    [InlineData("copilot", "node", ProfileFailModes.Closed, "deny")]
    public async Task An_expired_profile_gives_the_fail_mode_it_carries(string cli, string which, string failMode, string expected)
    {
        SignedIn(failMode: failMode);
        Store(string.Equals(which, "organisation", StringComparison.Ordinal) ? CachedNodePolicies.OrganisationRepository : Alpha, string.Equals(which, "organisation", StringComparison.Ordinal) ? RegoPolicyTestSupport.Baseline : AlphaBundle,
            failMode, DateTimeOffset.UtcNow - TimeSpan.FromDays(30));

        var (outcome, text) = await RunAsync(cli, _alpha, "ls");

        Assert.Equal(expected, outcome);
        Assert.Contains("has expired", text, StringComparison.Ordinal);
    }

    [Theory]
    [MemberData(nameof(Clis))]
    public async Task An_expired_organisation_profile_that_asks_does_not_soften_a_missing_node_profile(string cli)
    {
        SignedIn(alphaModule: null, failMode: ProfileFailModes.Ask);
        Store(CachedNodePolicies.OrganisationRepository, RegoPolicyTestSupport.Baseline, ProfileFailModes.Ask, DateTimeOffset.UtcNow - TimeSpan.FromDays(30));

        var (outcome, text) = await RunAsync(cli, _alpha, "ls");

        Assert.Equal("deny", outcome);
        Assert.Contains("no policy profile", text, StringComparison.Ordinal);
    }

    [Theory]
    [MemberData(nameof(Clis))]
    public async Task A_signed_in_pc_without_the_profile_of_its_repository_denies_with_the_fail_mode(string cli)
    {
        SignedIn(alphaModule: null);

        var (outcome, text) = await RunAsync(cli, _alpha, "ls");
        var (inBeta, _) = await RunAsync(cli, _beta, "ls");

        Assert.Equal("deny", outcome);
        Assert.Contains("no policy profile", text, StringComparison.Ordinal);
        Assert.Equal("allow", inBeta);
    }

    [Theory]
    [MemberData(nameof(Clis))]
    public async Task A_signed_in_pc_without_the_organisation_profile_denies_with_the_fail_mode(string cli)
    {
        SignedIn(organisationModule: null);

        var (outcome, text) = await RunAsync(cli, _beta, "ls");

        Assert.Equal("deny", outcome);
        Assert.Contains("no policy profile", text, StringComparison.Ordinal);
    }

    [Theory]
    [MemberData(nameof(Clis))]
    public async Task A_signed_in_pc_without_a_node_map_denies_with_the_fail_mode(string cli)
    {
        ServerConfigured();
        _state.WritePinnedKeys(Organisation, Pinned);
        Store(CachedNodePolicies.OrganisationRepository, RegoPolicyTestSupport.Baseline);

        var (outcome, text) = await RunAsync(cli, _alpha, "ls");

        Assert.Equal("deny", outcome);
        Assert.Contains("which node owns", text, StringComparison.Ordinal);
    }

    [Theory]
    [MemberData(nameof(Clis))]
    public async Task A_server_without_a_sign_in_denies_and_asks_the_developer_to_sign_in(string cli)
    {
        ServerConfigured();

        var (outcome, text) = await RunAsync(cli, _alpha, "ls");

        Assert.Equal("deny", outcome);
        Assert.Contains("Sign in", text, StringComparison.Ordinal);
    }

    [Theory]
    [MemberData(nameof(Clis))]
    public async Task Without_a_server_configured_the_cached_profiles_change_nothing(string cli)
    {
        SignedIn();
        foreach (var variable in new[] { SignInSettings.ServerVariable, SignInSettings.IssuerVariable, SignInSettings.ClientIdVariable })
        {
            Environment.SetEnvironmentVariable(variable, null);
        }

        Environment.SetEnvironmentVariable(ResidentSettings.EnableVariable, "on");

        var (outcome, _) = await RunAsync(cli, _alpha, "make deploy");

        Assert.Equal("allow", outcome);
    }

    [Theory]
    [MemberData(nameof(Clis))]
    public async Task A_profile_module_that_errors_while_it_runs_denies_by_name_in_process(string cli)
    {
        SignedIn(alphaModule: Clash, failMode: ProfileFailModes.Ask);

        var (outcome, text) = await RunAsync(cli, _alpha, "ls");

        Assert.Equal("deny", outcome);
        Assert.Contains("The policy bundle node:node-a failed while it ran", text, StringComparison.Ordinal);
    }

    [Theory]
    [MemberData(nameof(Clis))]
    public async Task A_profile_module_that_errors_in_the_resident_process_denies_by_name(string cli)
    {
        SignedIn(alphaModule: Clash, failMode: ProfileFailModes.Ask);
        await using var host = await HoldingResidentAsync(Alpha, expectBundleError: true);

        var (outcome, text) = await RunAsync(cli, _alpha, "ls");

        Assert.Equal("deny", outcome);
        Assert.Contains("The policy bundle node:node-a failed while it ran", text, StringComparison.Ordinal);
    }

    [Theory]
    [MemberData(nameof(Clis))]
    public async Task The_resident_process_answering_and_staying_silent_give_the_same_decisions(string cli)
    {
        SignedIn();
        Environment.SetEnvironmentVariable(ResidentSettings.EnableVariable, "on");
        Environment.SetEnvironmentVariable(ResidentSettings.BudgetVariable, "10000");
        string[] commands = ["rm -rf build", "make deploy", "ls"];
        var silent = new List<(string, string)>();
        foreach (var command in commands)
        {
            silent.Add(await RunAsync(cli, _alpha, command));
        }

        await using var host = await HoldingResidentAsync(Alpha, expectBundleError: false);
        var answering = new List<(string, string)>();
        foreach (var command in commands)
        {
            answering.Add(await RunAsync(cli, _alpha, command));
        }

        Assert.Equal(["deny", "deny", "allow"], silent.Select(r => r.Item1), StringComparer.Ordinal);
        Assert.Equal(silent, answering);
    }

    /// <summary>A resident process on the state folder that holds the cached profiles. Its server link never reaches a server, so it
    /// keeps what the cache holds.</summary>
    private async Task<HostedResident> HoldingResidentAsync(string repository, bool expectBundleError)
    {
        var signIn = new SignInSettings(new Uri("https://sentinel.example.com"), new Uri("https://login.example.com"), "plugin", "openid");
        var tokens = new TokenSession(new OidcDeviceClient(new HttpClient(), signIn, TimeProvider.System), null, TimeProvider.System);
        tokens.Set(new TokenSet("access", null, DateTimeOffset.UtcNow.AddHours(1)));
        var host = new HostedResident(
            _stateRoot, compilers: RegoPolicyTestSupport.Compilers(new ChildProcessCompiler()), tokens: tokens,
            server: new ServerLinkSettings(new Uri("https://sentinel.example.com"), ServerLinkTiming.Default, new UnreachableHandler()));
        await host.WaitUntilListeningAsync();
        var client = new ResidentClient(host.Settings);
        var deadline = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(60);
        while (true)
        {
            var answer = await client.SendAsync(new ResidentRequest { Op = ResidentOps.EvaluateProfile, Repository = repository, Input = "{}" }, TimeSpan.FromSeconds(5));
            if (expectBundleError ? answer?.BundleError == true : answer?.Ok == true)
            {
                return host;
            }

            if (DateTimeOffset.UtcNow > deadline)
            {
                await host.DisposeAsync();
                throw new TimeoutException("the resident process did not load the cached profile");
            }

            await Task.Delay(100);
        }
    }

    private sealed class UnreachableHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            throw new HttpRequestException("no server in this test");
    }

    private sealed class FixedClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
