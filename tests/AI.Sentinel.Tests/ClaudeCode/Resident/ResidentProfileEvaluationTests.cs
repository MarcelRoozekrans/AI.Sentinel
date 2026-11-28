using AI.Sentinel.ClaudeCode;
using AI.Sentinel.ClaudeCode.Policy;
using AI.Sentinel.ClaudeCode.Policy.Rego;
using AI.Sentinel.ClaudeCode.Policy.Repository;
using AI.Sentinel.ClaudeCode.Resident;
using AI.Sentinel.ClaudeCode.SignIn;
using AI.Sentinel.Profiles;
using AI.Sentinel.Tests.ClaudeCode.Policy;
using AI.Sentinel.Tests.Profiles;
using Xunit;

namespace AI.Sentinel.Tests.ClaudeCode.Resident;

/// <summary>The profiles of the server are asked of the resident process first and then evaluated in the hook (#729), within the one
/// budget of the call. The resident process answers only with the module of the profile the hook verified, so whether it answered never
/// changes the decision, and a module that fails there denies by name without a second run in the hook.</summary>
[Collection("NonParallel")]
public class ResidentProfileEvaluationTests : IDisposable
{
    private const string Repository = "github.com/acme/alpha";
    private const string Input = """{"kind":"shell","details":{"shell":{"commands":[{"name":"rm","args":["-rf","build"]}]}}}""";

    private readonly string _state = ResidentTestSupport.NewDir();
    private readonly ProfileSigningKey _key = ProfileSigningKey.Generate();

    public void Dispose()
    {
        ResidentTestSupport.Delete(_state);
        GC.SuppressFinalize(this);
    }

    private PinnedProfileKeys Pinned => PinnedProfileKeys.Create([_key.PublicKey]);

    private ResidentState State() => new(ResidentPaths.Prepare(new ResidentSettings(_state, ResidentSettings.DefaultIdleTimeout, ResidentSettings.DefaultBudget)));

    private ResidentState StoreBaseline()
    {
        var state = State();
        var signed = new ProfileSigner(_key).Issue(SignedProfileTests.Sample() with
        {
            Organisation = "acme",
            Repository = Repository,
            Module = RegoPolicyTestSupport.Baseline,
            ModuleHash = "sha256:baseline",
        });
        Assert.True(state.StoreProfile(signed, Pinned, "acme", Repository, DateTimeOffset.UtcNow, CachedNodePolicies.SlotOf(Repository)).IsAccepted);
        return state;
    }

    private CachedNodePolicies Policies(ResidentState state, IResidentProfiles? resident) =>
        new(state, Pinned, "acme", () => DateTimeOffset.UtcNow, ProfileDecider.CompiledDirectory(state), RegoPolicyTestSupport.Compilers(new ChildProcessCompiler()), resident);

    [Fact]
    public void The_resident_answer_is_used_and_names_the_hash_of_the_module_text_not_the_signed_field()
    {
        var resident = new FakeResidentProfiles(() => new RegoDecision(DecisionOutcome.Guidance, ["warm module"]));

        var decision = Policies(StoreBaseline(), resident).ForRepository(Repository, Input);

        Assert.Equal(["warm module"], decision!.Reasons);
        // The profile's module_hash field says sha256:baseline; the hook names the module it would evaluate itself.
        Assert.Equal([(Repository, ProfileDecider.ModuleHashOf(RegoPolicyTestSupport.Baseline))], resident.Asked);
    }

    [Fact]
    public void A_bundle_error_of_the_organisation_ends_the_order_before_the_node_and_the_folder()
    {
        var policies = new AI.Sentinel.Tests.ClaudeCode.Repository.RepositoryTestSupport.FakePolicies(
            _ => throw new PolicyBundleException("organisation module failed"),
            (_, _) => new RegoDecision(DecisionOutcome.Deny, ["node forbids it"]));
        var folder = new FakePolicyEvaluator(OutcomeDecision.InProcess, () => new RegoDecision(DecisionOutcome.Deny, ["folder forbids it"]));
        using var policy = LocalPolicy.ForEvaluators("v1", ["folder"], "/work/repo", [folder], FailModeTests.Profile(ProfileFailModes.Ask));
        policy.RepositoryPolicy = new RepositoryPolicy(new RepositoryScope(Repository, "node-a", StrictMode: true), policies);

        var (decisions, failed) = policy.RepositoryPolicy.Evaluate("{}");
        var output = policy.Decide(new AI.Sentinel.ClaudeCode.HookOutput { Decision = AI.Sentinel.ClaudeCode.HookDecision.Allow }, PolicyClis.ClaudeCode, "Bash",
            System.Text.Json.JsonDocument.Parse("""{"command":"ls"}""").RootElement, "s");

        Assert.True(failed);
        Assert.Equal(["organisation"], Assert.Single(decisions).Sources);
        Assert.Equal(DecisionOutcome.Deny, output.Outcome!.Outcome);
        Assert.Equal(["organisation"], output.Outcome.Sources);
        Assert.Equal(2, policies.Calls);
        Assert.Equal(0, folder.Calls);
    }

    [Fact]
    public void A_silent_resident_process_leaves_the_call_to_the_module_in_this_process()
    {
        var resident = new FakeResidentProfiles(() => null);

        var decision = Policies(StoreBaseline(), resident).ForRepository(Repository, Input);

        Assert.Equal(DecisionOutcome.Deny, decision!.Outcome);
        Assert.Contains("recursive delete", decision.Reasons, StringComparer.Ordinal);
        Assert.Single(resident.Asked);
    }

    [Fact]
    public void A_module_that_failed_in_the_resident_process_is_not_run_again_here_and_denies_by_name()
    {
        var resident = new FakeResidentProfiles(() => throw PolicyBundleException.FromResident("InvalidOperationException"));
        var policy = new RepositoryPolicy(new RepositoryScope(Repository, "node-a", StrictMode: true), Policies(StoreBaseline(), resident));

        var decisions = policy.Decisions(Input);

        // The organisation has no profile cached, so the node's bundle is the one decision: the denial by name, not the module's own deny.
        var denial = Assert.Single(decisions);
        Assert.Equal(DecisionOutcome.Deny, denial.Outcome);
        Assert.Equal(["node:node-a"], denial.Sources);
        Assert.Contains("The policy bundle node:node-a failed while it ran", denial.Reason, StringComparison.Ordinal);
        Assert.DoesNotContain("recursive delete", denial.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void A_profile_that_is_not_accepted_is_never_asked_of_the_resident_process()
    {
        var state = StoreBaseline();
        var resident = new FakeResidentProfiles(() => new RegoDecision(DecisionOutcome.Allow, ["warm"]));
        var other = new CachedNodePolicies(
            state, PinnedProfileKeys.Create([ProfileSigningKey.Generate().PublicKey]), "acme", () => DateTimeOffset.UtcNow,
            ProfileDecider.CompiledDirectory(state), compilers: null, resident);

        Assert.Null(other.ForRepository(Repository, Input));
        Assert.Null(other.Organisation(Input));
        Assert.Empty(resident.Asked);
    }

    [Fact]
    public async Task The_resident_process_answers_only_with_the_module_the_hook_verified()
    {
        await using var host = new HostedResident(_state, compilers: RegoPolicyTestSupport.Compilers(new ChildProcessCompiler()));
        await host.WaitUntilListeningAsync();
        using var service = new ResidentService(RegoPolicyTestSupport.Compilers(new ChildProcessCompiler()));
        service.InstallProfile(Repository, service.LoadProfileModule(State(), RegoPolicyTestSupport.Baseline), DateTimeOffset.UtcNow.AddHours(1), "sha256:baseline");

        var same = service.Answer(new ResidentRequest { Op = ResidentOps.EvaluateProfile, Repository = Repository, ModuleHash = "sha256:baseline", Input = Input });
        var other = service.Answer(new ResidentRequest { Op = ResidentOps.EvaluateProfile, Repository = Repository, ModuleHash = "sha256:newer", Input = Input });
        var unnamed = service.Answer(new ResidentRequest { Op = ResidentOps.EvaluateProfile, Repository = Repository, Input = Input });

        Assert.Equal("deny", same.Outcome);
        Assert.False(other.Ok);
        Assert.False(other.BundleError);
        Assert.Null(ResidentDecisionWire.FromResponse(other));
        Assert.Equal("deny", unnamed.Outcome);
        // Over the wire, a process that holds no profile for the repository gives no answer, and the hook evaluates it itself.
        Assert.Null(new ResidentClient(host.Settings).EvaluateProfile(Repository, "sha256:baseline", Input, TimeSpan.FromSeconds(5)));
    }

    [Fact]
    public void The_budget_is_shared_by_every_exchange_of_the_call_and_a_miss_silences_the_rest()
    {
        var budget = new ResidentBudget(TimeSpan.FromSeconds(10));
        var asked = 0;

        Assert.Equal("first", budget.Spend(left => { asked++; Assert.True(left <= TimeSpan.FromSeconds(10)); return "first"; }));
        Assert.Null(budget.Spend<string>(_ => { asked++; return null; }));
        Assert.Null(budget.Spend(_ => { asked++; return "after a miss"; }));
        Assert.Equal(2, asked);

        var spent = new ResidentBudget(TimeSpan.Zero);
        Assert.Null(spent.Spend(_ => { asked++; return "never"; }));
        Assert.Equal(2, asked);

        var failing = new ResidentBudget(TimeSpan.FromSeconds(10));
        Assert.Throws<PolicyBundleException>(() => failing.Spend<string>(_ => throw new PolicyBundleException("bundle")));
        Assert.Equal("still asked", failing.Spend(_ => "still asked"));
    }

    [Fact]
    public void A_hook_that_did_not_find_the_process_running_does_not_ask_it_for_a_profile()
    {
        var env = new Dictionary<string, string?>(StringComparer.Ordinal) { [ResidentSettings.EnableVariable] = "on", [ResidentSettings.DirectoryVariable] = _state };

        var session = ResidentSession.Open(env, _ => false)!;

        Assert.Equal(ResidentStart.Failed, session.Start);
        Assert.Null(session.Evaluate(Repository, "sha256:baseline", Input));
    }

    [Fact]
    public void Sign_in_settings_that_cannot_be_used_still_count_as_a_server_so_the_fail_mode_applies()
    {
        var env = new Dictionary<string, string?>(StringComparer.Ordinal)
        {
            [SignInSettings.ServerVariable] = "http://sentinel.example.com",
            [ResidentSettings.DirectoryVariable] = _state,
        };

        var profiles = HookProfiles.Open(env, _state, resident: null, compilers: null);

        Assert.Null(profiles.Repository);
        Assert.Same(FailModeContext.NotSignedIn, profiles.FailMode);
    }

    [Fact]
    public void Without_any_server_setting_there_is_no_fail_mode()
    {
        var env = new Dictionary<string, string?>(StringComparer.Ordinal) { [ResidentSettings.DirectoryVariable] = _state };

        Assert.Equal(new HookProfiles(null, null), HookProfiles.Open(env, _state, resident: null, compilers: null));
    }

    private sealed class FakeResidentProfiles(Func<RegoDecision?> answer) : IResidentProfiles
    {
        public List<(string Repository, string ModuleHash)> Asked { get; } = [];

        public RegoDecision? Evaluate(string repository, string moduleHash, string inputJson)
        {
            Asked.Add((repository, moduleHash));
            return answer();
        }
    }
}
