using System.Diagnostics;
using System.Text.Json;
using AI.Sentinel.ClaudeCode;
using AI.Sentinel.ClaudeCode.Policy;
using AI.Sentinel.ClaudeCode.Policy.Rego;
using AI.Sentinel.ClaudeCode.Resident;
using AI.Sentinel.Tests.ClaudeCode.Policy;
using AI.Sentinel.Tests.Helpers;
using Xunit;

namespace AI.Sentinel.Tests.ClaudeCode.Resident;

/// <summary>The evaluation order of #658: the resident process answers first; when it does not answer within its budget the hook
/// evaluates the module in-process; when that fails too the server is asked, once there is one. Each decision records where it was
/// made, and the whole decision stays within the 50 ms of ADR-007.</summary>
[Collection("NonParallel")]
public class EvaluationOrderTests : IDisposable
{
    private static readonly HookOutput Allowed = new() { Decision = HookDecision.Allow };

    private readonly string _folder = RegoPolicyTestSupport.StandardFolder();
    private readonly string _state = ResidentTestSupport.NewDir();

    public void Dispose()
    {
        RegoPolicyTestSupport.Delete(_folder);
        ResidentTestSupport.Delete(_state);
        GC.SuppressFinalize(this);
    }

    private static JsonElement Json(string json) => JsonDocument.Parse(json).RootElement;

    private Dictionary<string, string?> Env(int budgetMs = 15)
    {
        var env = RegoPolicyTestSupport.Env();
        env[ResidentSettings.EnableVariable] = "on";
        env[ResidentSettings.DirectoryVariable] = _state;
        env[ResidentSettings.BudgetVariable] = budgetMs.ToString(System.Globalization.CultureInfo.InvariantCulture);
        return env;
    }

    private LocalPolicy Load(int budgetMs = 15, Func<ResidentLaunch, bool>? start = null) =>
        LocalPolicy.Load(
            _folder, Env(budgetMs), "/work/repo", RegoPolicyTestSupport.Compilers(new ChildProcessCompiler()),
            ResidentSession.Open(Env(budgetMs), start ?? (_ => false)));

    /// <summary>Loads the module in the resident process: the first call after a start is slower than the budget.</summary>
    private void Warm()
    {
        using var policy = Load(budgetMs: 60_000);
        policy.Decide(Allowed, PolicyClis.ClaudeCode, "Bash", Json("""{"command":"ls"}"""), "s");
    }

    [Fact]
    public async Task The_resident_process_answers_first_and_the_decision_says_so()
    {
        RegoPolicyTestSupport.Prime(_folder);
        await using var host = new HostedResident(_state, compilers: RegoPolicyTestSupport.Compilers(new ChildProcessCompiler()));
        await host.WaitUntilListeningAsync();
        Warm();

        using var policy = Load();
        var output = policy.Decide(Allowed, PolicyClis.ClaudeCode, "Bash", Json("""{"command":"rm -rf build"}"""), "s");

        Assert.Equal(DecisionOutcome.Deny, output.Outcome!.Outcome);
        Assert.Equal("recursive delete", output.Reason);
        Assert.Equal(OutcomeDecision.Resident, output.Outcome.DecidedAt);
        Assert.Contains("decided=resident", output.Outcome.Summary(), StringComparison.Ordinal);
    }

    /// <summary>A hook that starts the process does not wait for it, so it decides in-process even when the new process listens by
    /// the time the hook evaluates. Which place answers would otherwise depend on how fast the process starts.</summary>
    [Fact]
    public async Task A_hook_that_started_the_resident_process_decides_in_process_even_when_it_already_listens()
    {
        RegoPolicyTestSupport.Prime(_folder);
        HostedResident? host = null;
        try
        {
            using var policy = Load(budgetMs: 60_000, start: _ =>
            {
                host = new HostedResident(_state, compilers: RegoPolicyTestSupport.Compilers(new ChildProcessCompiler()));
                host.WaitUntilListeningAsync().Wait(TestContext.Current.CancellationToken);
                Warm();
                return true;
            });

            var output = policy.Decide(Allowed, PolicyClis.ClaudeCode, "Bash", Json("""{"command":"rm -rf build"}"""), "s");

            Assert.NotNull(host);
            Assert.Equal(DecisionOutcome.Deny, output.Outcome!.Outcome);
            Assert.Equal(OutcomeDecision.InProcess, output.Outcome.DecidedAt);
        }
        finally
        {
            if (host is not null)
            {
                await host.DisposeAsync();
            }
        }
    }

    [Fact]
    public async Task The_resident_answer_is_the_answer_of_an_in_process_evaluation()
    {
        RegoPolicyTestSupport.Prime(_folder);
        await using var host = new HostedResident(_state, compilers: RegoPolicyTestSupport.Compilers(new ChildProcessCompiler()));
        await host.WaitUntilListeningAsync();
        Warm();
        var calls = new[]
        {
            ("Bash", """{"command":"git push origin main"}"""), ("Bash", """{"command":"ls -la"}"""), ("Bash", """{"command":"make"}"""),
            ("mcp__github__create_issue", "{}"), ("Write", """{"file_path":"/etc/cron.d/x"}"""),
        };

        foreach (var (tool, input) in calls)
        {
            using var viaResident = Load();
            using var inProcess = LocalPolicy.Load(_folder, RegoPolicyTestSupport.Env(), "/work/repo", RegoPolicyTestSupport.Compilers(new ChildProcessCompiler()));
            var a = viaResident.Decide(Allowed, PolicyClis.ClaudeCode, tool, Json(input), "s");
            var b = inProcess.Decide(Allowed, PolicyClis.ClaudeCode, tool, Json(input), "s");

            Assert.Equal(b.Decision, a.Decision);
            Assert.Equal(b.Reason, a.Reason);
            Assert.Equal(b.Outcome?.Outcome, a.Outcome?.Outcome);
            Assert.Equal(b.Outcome?.PolicyVersion, a.Outcome?.PolicyVersion);
        }
    }

    [Fact]
    public async Task The_severity_outcomes_of_the_policy_come_from_the_resident_process_too()
    {
        var folder = RegoPolicyTestSupport.Folder(("p/sev.rego", "package sentinel\nimport rego.v1\nseverity_actions contains {\"severity\": \"high\", \"outcome\": \"ask\"}\n"));
        try
        {
            RegoPolicyTestSupport.Prime(folder);
            await using var host = new HostedResident(_state, compilers: RegoPolicyTestSupport.Compilers(new ChildProcessCompiler()));
            await host.WaitUntilListeningAsync();
            for (var attempt = 0; attempt < 2; attempt++)
            {
                using var policy = LocalPolicy.Load(
                    folder, Env(attempt == 0 ? 60_000 : 15), "/work/repo", RegoPolicyTestSupport.Compilers(new ChildProcessCompiler()),
                    ResidentSession.Open(Env(attempt == 0 ? 60_000 : 15), _ => false));

                Assert.True(policy.Severities().TryGet(AI.Sentinel.Detection.Severity.High, out var outcome));
                Assert.Equal(DecisionOutcome.Ask, outcome);
            }
        }
        finally
        {
            RegoPolicyTestSupport.Delete(folder);
        }
    }

    [Fact]
    public void Without_a_resident_process_the_call_is_decided_in_process_and_the_hook_starts_one()
    {
        RegoPolicyTestSupport.Prime(_folder);
        var starts = new List<ResidentLaunch>();

        using var policy = Load(start: l => { starts.Add(l); return true; });
        var output = policy.Decide(Allowed, PolicyClis.ClaudeCode, "Bash", Json("""{"command":"rm -rf build"}"""), "s");

        Assert.Equal("recursive delete", output.Reason);
        Assert.Equal(OutcomeDecision.InProcess, output.Outcome!.DecidedAt);
        Assert.Single(starts);
    }

    [Fact]
    public void A_resident_process_that_does_not_answer_within_the_budget_is_left_behind_for_an_in_process_decision()
    {
        RegoPolicyTestSupport.Prime(_folder);
        var settings = ResidentSettings.FromEnvironment(Env())!;
        using var silent = new SilentListener(settings);

        var watch = Stopwatch.StartNew();
        using var policy = Load();
        var loaded = watch.Elapsed;
        var output = policy.Decide(Allowed, PolicyClis.ClaudeCode, "Bash", Json("""{"command":"rm -rf build"}"""), "s");
        watch.Stop();

        Assert.Equal("recursive delete", output.Reason);
        Assert.Equal(OutcomeDecision.InProcess, output.Outcome!.DecidedAt);
        // The budget is spent once per call: the second evaluation of the call does not wait for the resident process again.
        Assert.True(watch.Elapsed - loaded < TimeSpan.FromMilliseconds(40), $"decide took {(watch.Elapsed - loaded).TotalMilliseconds:F1} ms after load");
    }

    [Fact]
    public void The_budget_runs_from_the_call_and_a_spent_budget_asks_nobody()
    {
        RegoPolicyTestSupport.Prime(_folder);
        var settings = ResidentSettings.FromEnvironment(Env())!;
        using var silent = new SilentListener(settings);
        var client = new ResidentClient(settings);

        var watch = Stopwatch.StartNew();
        var none = client.Evaluate(_folder, "v", RegoPolicyTestSupport.SharedCache, "{}", TimeSpan.FromMilliseconds(50));
        watch.Stop();
        var spent = new ResidentPolicyEvaluator(new ResidentClient(settings with { Budget = TimeSpan.Zero }), _folder, "v", RegoPolicyTestSupport.SharedCache);

        Assert.Null(none);
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(5), $"the exchange took {watch.Elapsed.TotalMilliseconds:F0} ms");
        Assert.Null(spent.Evaluate("{}"));
    }

    [Fact]
    public void A_policy_folder_that_changed_since_it_was_read_is_not_evaluated_in_place_of_the_recorded_version()
    {
        RegoPolicyTestSupport.Prime(_folder);
        var cache = RegoPolicyTestSupport.SharedCache;
        var compilers = RegoPolicyTestSupport.Compilers(new ChildProcessCompiler());
        var recorded = PolicySources.Load(_folder).Version;
        using (LocalPolicy.LoadRecorded(_folder, cache, compilers, recorded))
        {
        }

        File.AppendAllText(Directory.GetFiles(_folder, "*.rego", SearchOption.AllDirectories).First(), "\n# changed\n");

        Assert.Throws<InvalidOperationException>(() => LocalPolicy.LoadRecorded(_folder, cache, compilers, recorded));
    }

    [Fact]
    public void A_state_folder_that_is_open_to_others_is_not_talked_to_and_the_call_is_blocked()
    {
        if (OperatingSystem.IsWindows())
        {
            Assert.Skip("Needs Unix directory modes.");
            return;
        }

        RegoPolicyTestSupport.Prime(_folder);
        var sibling = _state + ".private";
        Directory.CreateDirectory(sibling);
        File.SetUnixFileMode(sibling, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute | UnixFileMode.OtherRead | UnixFileMode.OtherExecute);
        try
        {
            var session = ResidentSession.Open(Env(), _ => throw new InvalidOperationException("nothing is started"))!;

            // The hooks fail closed: what the folder holds, such as the node map, could be another user's, so the load fails and
            // the caller blocks the call.
            var error = Assert.Throws<UnauthorizedAccessException>(
                () => LocalPolicy.Load(_folder, Env(), "/work/repo", RegoPolicyTestSupport.Compilers(new ChildProcessCompiler()), session));

            Assert.Equal(ResidentStart.Unusable, session.Start);
            Assert.Contains(_state, error.Message, StringComparison.Ordinal);
            Assert.Contains("open to other users", error.Message, StringComparison.Ordinal);
        }
        finally
        {
            ResidentTestSupport.Delete(sibling);
        }
    }

    [Fact]
    public async Task A_resident_process_that_fails_the_request_is_no_answer()
    {
        RegoPolicyTestSupport.Prime(_folder);
        var folder = RegoPolicyTestSupport.Folder(("p/bad.rego", "package sentinel\nthis is not rego\n"));
        try
        {
            await using var host = new HostedResident(_state, compilers: RegoPolicyTestSupport.Compilers(new ChildProcessCompiler()));
            await host.WaitUntilListeningAsync();

            // The resident process cannot load it and neither can the hook: the call blocks as before, it does not pass.
            Assert.ThrowsAny<Exception>(() => LocalPolicy.Load(
                folder, Env(), "/work/repo", RegoPolicyTestSupport.Compilers(new ChildProcessCompiler()), ResidentSession.Open(Env(), _ => false)));
        }
        finally
        {
            RegoPolicyTestSupport.Delete(folder);
        }
    }

    [Fact]
    public void The_order_is_resident_then_in_process_then_server_and_stops_at_the_first_answer()
    {
        var resident = new FakePolicyEvaluator(OutcomeDecision.Resident, () => null);
        var inProcess = new FakePolicyEvaluator(OutcomeDecision.InProcess, () => throw new InvalidOperationException("module failed"));
        var server = new FakePolicyEvaluator(OutcomeDecision.Server, () => FakePolicyEvaluator.Deny("server says no"));
        var never = new FakePolicyEvaluator("never", () => FakePolicyEvaluator.Deny("not reached"));

        var answer = new EvaluationOrder([resident, inProcess, server, never]).Evaluate("{}");

        Assert.Equal(OutcomeDecision.Server, answer.Place);
        Assert.Equal(["server says no"], answer.Decision.Reasons);
        Assert.Equal([1, 1, 1, 0], [resident.Calls, inProcess.Calls, server.Calls, never.Calls]);
    }

    [Fact]
    public void An_earlier_answer_means_the_later_evaluators_are_not_asked()
    {
        var resident = new FakePolicyEvaluator(OutcomeDecision.Resident, () => FakePolicyEvaluator.Deny("no"));
        var inProcess = new FakePolicyEvaluator(OutcomeDecision.InProcess, () => FakePolicyEvaluator.Deny("also no"));

        var answer = new EvaluationOrder([resident, inProcess]).Evaluate("{}");

        Assert.Equal(OutcomeDecision.Resident, answer.Place);
        Assert.Equal(0, inProcess.Calls);
    }

    [Fact]
    public void When_every_evaluator_fails_the_first_failure_is_thrown_so_the_hook_blocks()
    {
        var resident = new FakePolicyEvaluator(OutcomeDecision.Resident, () => null);
        var inProcess = new FakePolicyEvaluator(OutcomeDecision.InProcess, () => throw new InvalidOperationException("module failed"));

        var error = Assert.Throws<InvalidOperationException>(() => new EvaluationOrder([resident, inProcess]).Evaluate("{}"));

        Assert.Equal("module failed", error.Message);
    }

    [Fact]
    public void When_nobody_answers_and_nobody_fails_the_order_throws_too()
    {
        var resident = new FakePolicyEvaluator(OutcomeDecision.Resident, () => null);

        Assert.Throws<InvalidOperationException>(() => new EvaluationOrder([resident]).Evaluate("{}"));
    }

    [Fact]
    public void The_places_have_their_documented_names()
    {
        Assert.Equal("resident", OutcomeDecision.Resident);
        Assert.Equal("in-process", OutcomeDecision.InProcess);
        Assert.Equal("server", OutcomeDecision.Server);
    }

    [Fact]
    public async Task The_whole_decision_stays_within_50_ms_whether_the_resident_process_answers_or_is_stuck()
    {
        RegoPolicyTestSupport.Prime(_folder);
        var input = Json("""{"command":"cat a | grep b && git push origin main"}""");
        await using var host = new HostedResident(_state, compilers: RegoPolicyTestSupport.Compilers(new ChildProcessCompiler()));
        await host.WaitUntilListeningAsync();
        Warm();
        var answering = P95(() => Load(), input);
        await host.DisposeAsync();
        using var silent = new SilentListener(ResidentSettings.FromEnvironment(Env())!);
        var stuck = P95(() => Load(), input);

        Assert.True(answering < 50, $"resident answers: p95 {answering:F1} ms");
        Assert.True(stuck < 50, $"resident stuck: p95 {stuck:F1} ms");
    }

    private static double P95(Func<LocalPolicy> load, JsonElement input)
    {
        var millis = new List<double>();
        for (var i = 0; i < 30; i++)
        {
            var watch = Stopwatch.StartNew();
            using var policy = load();
            policy.FindingSink("SEC-02", "low");
            var output = policy.Decide(Allowed, PolicyClis.ClaudeCode, "Bash", input, "s");
            watch.Stop();
            Assert.Equal(DecisionOutcome.Ask, output.Outcome!.Outcome);
            millis.Add(watch.Elapsed.TotalMilliseconds);
        }

        millis.Sort();
        return millis[(int)Math.Ceiling(millis.Count * 0.95) - 1];
    }

    [Fact]
    public async Task Without_the_setting_no_process_is_started_and_the_output_is_as_before()
    {
        RegoPolicyTestSupport.Prime(_folder);
        var starts = 0;
        using var env = new EnvironmentScope(
            (LocalPolicy.FolderVariable, _folder), ("SENTINEL_HOOK_POLICY_CACHE_DIR", RegoPolicyTestSupport.SharedCache),
            (ResidentSettings.EnableVariable, null), (HookAuditTestSupport.SqliteVar, "off"), ("SENTINEL_HOOK_HEADLESS", null));
        var stdout = new StringWriter();

        var exit = await AI.Sentinel.ClaudeCode.Cli.Program.RunAsync(
            ["pre-tool-use"], new StringReader("""{"session_id":"cc-1","tool_name":"Bash","tool_input":{"command":"git push"}}"""),
            stdout, new StringWriter(), new ExactMatchEmbeddingGenerator(), reviewer: null, policyCompilers: null,
            residentStart: _ => { starts++; return true; });

        Assert.Equal(0, exit);
        Assert.Contains("\"permissionDecision\":\"ask\"", stdout.ToString(), StringComparison.Ordinal);
        Assert.Equal(0, starts);
        Assert.False(Directory.Exists(_state));
    }
}
