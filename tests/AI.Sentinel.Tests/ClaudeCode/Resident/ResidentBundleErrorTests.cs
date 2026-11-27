using System.Net.Sockets;
using System.Text.Json;
using AI.Sentinel.ClaudeCode;
using AI.Sentinel.ClaudeCode.Policy;
using AI.Sentinel.ClaudeCode.Policy.Rego;
using AI.Sentinel.ClaudeCode.Resident;
using AI.Sentinel.Profiles;
using AI.Sentinel.Tests.ClaudeCode.Policy;
using Xunit;

namespace AI.Sentinel.Tests.ClaudeCode.Resident;

/// <summary>A bundle that errors while it runs in the resident process (#716) denies by bundle name, as ADR-237 asks, whatever the
/// fail mode and whatever a later place would answer. A resident process that is missing, refuses the connection or gets no budget
/// is no answer, and the next place is asked as before.</summary>
[Collection("NonParallel")]
public class ResidentBundleErrorTests : IDisposable
{
    // Redefines the decision rule of the host, so OPA reports a conflict on every evaluation: it loads, and fails while it runs.
    private const string Clash = "package sentinel\nimport rego.v1\ndecision := {\"outcome\": \"allow\", \"reasons\": [\"mine\"]}\n";

    private static readonly HookOutput Allowed = new() { Decision = HookDecision.Allow };

    private readonly string _state = ResidentTestSupport.NewDir();
    private readonly List<string> _folders = [];

    public void Dispose()
    {
        ResidentTestSupport.Delete(_state);
        foreach (var folder in _folders)
        {
            RegoPolicyTestSupport.Delete(folder);
        }

        GC.SuppressFinalize(this);
    }

    private static JsonElement Json(string json) => JsonDocument.Parse(json).RootElement;

    private static FakePolicyEvaluator InProcessAllows() =>
        new(OutcomeDecision.InProcess, () => new RegoDecision(DecisionOutcome.Allow, ["the in-process module allows"]));

    private static IReadOnlyList<IRegoCompiler> Compilers() => RegoPolicyTestSupport.Compilers(new ChildProcessCompiler());

    private string ClashFolder()
    {
        var folder = RegoPolicyTestSupport.Folder(("clash/clash.rego", Clash));
        _folders.Add(folder);
        RegoPolicyTestSupport.Prime(folder);
        return folder;
    }

    private static ResidentPolicyEvaluator ResidentFor(ResidentSettings settings, string folder) =>
        new(new ResidentClient(settings), Path.GetFullPath(folder), PolicySources.Load(folder).Version, Path.GetFullPath(RegoPolicyTestSupport.SharedCache));

    private static ResidentRequest EvaluateRequest(string folder, string version) => new()
    {
        Op = ResidentOps.Evaluate,
        Folder = Path.GetFullPath(folder),
        Version = version,
        CacheDirectory = Path.GetFullPath(RegoPolicyTestSupport.SharedCache),
        Input = """{"tool":"Bash","command":"echo secret-in-the-input"}""",
    };

    [Theory]
    [InlineData(ProfileFailModes.Closed)]
    [InlineData(ProfileFailModes.Ask)]
    public async Task A_bundle_that_errors_in_the_resident_process_denies_by_name_even_when_the_in_process_module_would_allow(string failMode)
    {
        var folder = ClashFolder();
        await using var host = new HostedResident(_state, compilers: Compilers());
        await host.WaitUntilListeningAsync();
        var inProcess = InProcessAllows();
        using var policy = LocalPolicy.ForEvaluators(
            "v1", ["clash"], "/work/repo", [ResidentFor(host.Settings with { Budget = TimeSpan.FromSeconds(60) }, folder), inProcess],
            FailModeTests.Profile(failMode));

        var output = policy.Decide(Allowed, PolicyClis.ClaudeCode, "Bash", Json("""{"command":"echo secret-in-the-input"}"""), "s");

        Assert.Equal(DecisionOutcome.Deny, output.Outcome!.Outcome);
        Assert.Equal(["policy:clash"], output.Outcome.Sources);
        Assert.Contains("The policy bundle clash failed while it ran", output.Reason, StringComparison.Ordinal);
        Assert.DoesNotContain("secret-in-the-input", output.Reason, StringComparison.Ordinal);
        Assert.Equal(0, inProcess.Calls);
    }

    [Fact]
    public async Task Without_a_fail_mode_a_bundle_error_in_the_resident_process_is_an_error_so_the_hook_blocks()
    {
        var folder = ClashFolder();
        await using var host = new HostedResident(_state, compilers: Compilers());
        await host.WaitUntilListeningAsync();
        var inProcess = InProcessAllows();
        using var policy = LocalPolicy.ForEvaluators(
            "v1", ["clash"], "/work/repo", [ResidentFor(host.Settings with { Budget = TimeSpan.FromSeconds(60) }, folder), inProcess], failMode: null);

        var error = Assert.Throws<PolicyBundleException>(
            () => policy.Decide(Allowed, PolicyClis.ClaudeCode, "Bash", Json("""{"command":"echo secret-in-the-input"}"""), "s"));

        Assert.DoesNotContain("secret-in-the-input", error.Message, StringComparison.Ordinal);
        Assert.Equal(0, inProcess.Calls);
    }

    [Theory]
    [InlineData("missing", ProfileFailModes.Closed)]
    [InlineData("missing", ProfileFailModes.Ask)]
    [InlineData("refused", ProfileFailModes.Closed)]
    [InlineData("refused", ProfileFailModes.Ask)]
    [InlineData("spent", ProfileFailModes.Closed)]
    [InlineData("spent", ProfileFailModes.Ask)]
    public async Task A_resident_process_that_cannot_be_reached_or_gets_no_budget_is_silence_and_the_next_place_answers(string how, string failMode)
    {
        var folder = ClashFolder();
        var settings = new ResidentSettings(_state, ResidentSettings.DefaultIdleTimeout, TimeSpan.FromSeconds(5));
        HostedResident? host = null;
        Socket? stale = null;
        try
        {
            switch (how)
            {
                case "refused":
                    // A socket that is bound and does not listen, so a connection to it is refused, as for one a dead process left.
                    stale = ResidentChannel.NewSocket();
                    stale.Bind(new UnixDomainSocketEndPoint(ResidentPaths.Socket(settings with { StateDirectory = ResidentPaths.Prepare(settings) })));
                    Assert.True(File.Exists(ResidentPaths.Socket(settings)));
                    break;
                case "spent":
                    // The resident process runs and would report the bundle error, but the call has no budget left to ask it.
                    host = new HostedResident(_state, compilers: Compilers());
                    await host.WaitUntilListeningAsync();
                    settings = host.Settings with { Budget = TimeSpan.Zero };
                    break;
            }

            var inProcess = InProcessAllows();
            using var policy = LocalPolicy.ForEvaluators("v1", ["clash"], "/work/repo", [ResidentFor(settings, folder), inProcess], FailModeTests.Profile(failMode));

            var output = policy.Decide(Allowed, PolicyClis.ClaudeCode, "Bash", Json("""{"command":"make"}"""), "s");

            Assert.Equal(DecisionOutcome.Allow, output.Outcome!.Outcome);
            Assert.Equal(OutcomeDecision.InProcess, output.Outcome.DecidedAt);
            Assert.Equal(1, inProcess.Calls);
        }
        finally
        {
            stale?.Dispose();
            if (host is not null)
            {
                await host.DisposeAsync();
            }
        }
    }

    [Fact]
    public void The_resident_service_answers_a_bundle_that_errors_while_it_runs_as_a_bundle_error_without_the_message()
    {
        var folder = ClashFolder();
        using var service = new ResidentService(Compilers());

        var response = service.Answer(EvaluateRequest(folder, PolicySources.Load(folder).Version));

        Assert.False(response.Ok);
        Assert.True(response.BundleError);
        Assert.DoesNotContain("secret-in-the-input", response.Error ?? "", StringComparison.Ordinal);
        Assert.Throws<PolicyBundleException>(() => ResidentDecisionWire.FromResponse(response));
    }

    [Fact]
    public void A_policy_folder_that_changed_since_the_hook_read_it_is_no_bundle_error_so_the_hook_evaluates_the_version_it_read()
    {
        var folder = ClashFolder();
        using var service = new ResidentService(Compilers());

        var response = service.Answer(EvaluateRequest(folder, "another-version"));

        Assert.False(response.Ok);
        Assert.False(response.BundleError);
        Assert.Null(ResidentDecisionWire.FromResponse(response));
    }

    [Fact]
    public void A_held_profile_whose_module_errors_while_it_runs_is_answered_as_a_bundle_error()
    {
        var folder = ClashFolder();
        using var service = new ResidentService(Compilers());
        service.InstallProfile("github.com/acme/app", RegoPolicy.Load(folder, RegoPolicyTestSupport.SharedCache, Compilers()), DateTimeOffset.UtcNow.AddHours(1));

        var response = service.Answer(new ResidentRequest
        {
            Op = ResidentOps.EvaluateProfile,
            Repository = "github.com/acme/app",
            Input = """{"tool":"Bash","command":"make"}""",
        });

        Assert.False(response.Ok);
        Assert.True(response.BundleError);
    }

    [Fact]
    public void An_error_response_that_is_not_a_bundle_error_is_no_answer_and_a_bundle_error_survives_the_wire()
    {
        var plain = new ResidentResponse { Error = "unknown operation 'x'" };
        var bundle = JsonSerializer.Deserialize(
            JsonSerializer.Serialize(ResidentDecisionWire.ToBundleError(new InvalidOperationException("secret-in-the-input")), ResidentJsonContext.Default.ResidentResponse),
            ResidentJsonContext.Default.ResidentResponse)!;

        Assert.Null(ResidentDecisionWire.FromResponse(plain));
        Assert.True(bundle.BundleError);
        Assert.Equal(nameof(InvalidOperationException), bundle.Error);
        var error = Assert.Throws<PolicyBundleException>(() => ResidentDecisionWire.FromResponse(bundle));
        Assert.DoesNotContain("secret-in-the-input", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void The_bundle_error_names_the_error_type_the_resident_saw_and_keeps_an_inner_error()
    {
        var inner = new InvalidOperationException("secret-in-the-input");

        Assert.Contains(nameof(InvalidOperationException), PolicyBundleException.FromResident(nameof(InvalidOperationException)).Message, StringComparison.Ordinal);
        Assert.Contains("unknown error", PolicyBundleException.FromResident(null).Message, StringComparison.Ordinal);
        Assert.Same(inner, new PolicyBundleException("the bundle failed", inner).InnerException);
        Assert.NotEmpty(new PolicyBundleException().Message);
    }
}
