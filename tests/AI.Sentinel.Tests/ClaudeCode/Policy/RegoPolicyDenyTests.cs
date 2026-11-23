using System.Diagnostics;
using System.Text.Json;
using AI.Sentinel.Audit;
using AI.Sentinel.ClaudeCode;
using AI.Sentinel.ClaudeCode.Policy;
using AI.Sentinel.Tests.Helpers;
using Xunit;

namespace AI.Sentinel.Tests.ClaudeCode.Policy;

/// <summary>A local Rego policy (#654) denies, asks and guides, the strictest outcome wins across the policy and the other
/// checks, and the decision stays within the 50 ms per call of ADR-007.</summary>
[Collection("NonParallel")]
public class RegoPolicyDenyTests : IDisposable
{
    private static readonly HookOutput Allowed = new() { Decision = HookDecision.Allow };

    private readonly string _folder = RegoPolicyTestSupport.StandardFolder();
    private readonly string _work = HookAuditTestSupport.NewTempDir();

    public void Dispose()
    {
        RegoPolicyTestSupport.Delete(_folder);
        HookAuditTestSupport.DeleteDir(_work);
        GC.SuppressFinalize(this);
    }

    private LocalPolicy Load(string root = "/work/repo") => LoadOf(_folder, root);

    private static LocalPolicy LoadOf(string folder, string root = "/work/repo") =>
        LocalPolicy.Load(folder, RegoPolicyTestSupport.Env(), root, [new ChildProcessCompiler()]);

    private static JsonElement Json(string json) => JsonDocument.Parse(json).RootElement;

    [Fact]
    public void A_tool_call_that_matches_a_deny_rule_is_blocked_with_the_reason_of_the_rule()
    {
        using var policy = Load();

        var output = policy.Decide(Allowed, PolicyClis.ClaudeCode, "Bash", Json("""{"command":"rm -rf build"}"""), "s-1");

        Assert.Equal(HookDecision.Block, output.Decision);
        Assert.Equal("recursive delete", output.Reason);
        Assert.Equal(DecisionOutcome.Deny, output.Outcome!.Outcome);
        Assert.Equal(16, output.Outcome.PolicyVersion.Length);
        Assert.Equal(["policy:org-baseline,team-guidance"], output.Outcome.Sources);
    }

    [Fact]
    public void An_ask_rule_gives_ask_and_a_guidance_rule_gives_guidance_and_an_allow_rule_gives_allow()
    {
        using var policy = Load();

        var ask = policy.Decide(Allowed, PolicyClis.ClaudeCode, "Bash", Json("""{"command":"git push origin main"}"""), "s");
        var guidance = policy.Decide(Allowed, PolicyClis.ClaudeCode, "mcp__github__create_issue", Json("{}"), "s");
        var allow = policy.Decide(Allowed, PolicyClis.ClaudeCode, "Bash", Json("""{"command":"ls -la"}"""), "s");

        Assert.Equal(DecisionOutcome.Ask, ask.Outcome!.Outcome);
        Assert.Equal("git push needs a person", ask.Reason);
        Assert.Equal(DecisionOutcome.Guidance, guidance.Outcome!.Outcome);
        Assert.Equal("prefer the gh CLI over the GitHub MCP server", guidance.Reason);
        Assert.Equal(DecisionOutcome.Allow, allow.Outcome!.Outcome);
        Assert.Equal(HookDecision.Allow, allow.Decision);
    }

    [Fact]
    public void The_strictest_outcome_wins_inside_the_policy_so_a_deny_beats_an_allow_of_another_bundle()
    {
        using var policy = Load();

        var output = policy.Decide(Allowed, PolicyClis.ClaudeCode, "Bash", Json("""{"command":"cat a && rm -r b"}"""), "s");

        Assert.Equal(DecisionOutcome.Deny, output.Outcome!.Outcome);
        Assert.Equal("recursive delete", output.Reason);
    }

    [Fact]
    public void The_policy_matches_on_the_findings_of_the_scan_and_sprintf_builds_the_reason()
    {
        using var policy = Load();
        policy.FindingSink("SEC-01", "critical");
        policy.FindingSink("SEC-02", "low");

        var output = policy.Decide(Allowed, PolicyClis.ClaudeCode, "Read", Json("""{"file_path":"/work/repo/a.cs"}"""), "s");

        Assert.Equal(DecisionOutcome.Deny, output.Outcome!.Outcome);
        Assert.Equal("critical finding from SEC-01 (critical)", output.Reason);
    }

    [Fact]
    public void A_path_outside_the_repository_is_seen_by_the_policy()
    {
        using var policy = Load();

        var outside = policy.Decide(Allowed, PolicyClis.ClaudeCode, "Write", Json("""{"file_path":"/etc/cron.d/x"}"""), "s");
        var inside = policy.Decide(Allowed, PolicyClis.ClaudeCode, "Write", Json("""{"file_path":"/work/repo/a.cs"}"""), "s");

        Assert.Equal("write outside the repository", outside.Reason);
        Assert.Same(Allowed, inside);
    }

    [Fact]
    public void A_copilot_call_is_judged_by_its_own_tool_names()
    {
        using var policy = Load();

        var output = policy.Decide(Allowed, PolicyClis.Copilot, "bash", Json("""{"command":"rm -fr x"}"""), "s");

        Assert.Equal(HookDecision.Block, output.Decision);
        Assert.Equal("recursive delete", output.Reason);
    }

    [Fact]
    public void A_command_the_parser_cannot_read_asks_even_when_the_policy_allows()
    {
        var allowing = RegoPolicyTestSupport.Folder(("p/allow.rego", "package sentinel\nimport rego.v1\nallow contains \"all fine\" if true\n"));
        try
        {
            using var policy = LoadOf(allowing);

            var output = policy.Decide(Allowed, PolicyClis.ClaudeCode, "Bash", Json("""{"command":"echo $(whoami)"}"""), "s");

            Assert.Equal(DecisionOutcome.Ask, output.Outcome!.Outcome);
            Assert.Equal(LocalPolicy.UnparseableReason, output.Outcome.Reason);
            Assert.Equal([LocalPolicy.ParserSource], output.Outcome.Sources);
        }
        finally
        {
            RegoPolicyTestSupport.Delete(allowing);
        }
    }

    [Fact]
    public void A_patch_without_readable_targets_asks_even_when_the_policy_allows()
    {
        var allowing = RegoPolicyTestSupport.Folder(("p/allow.rego", "package sentinel\nimport rego.v1\nallow contains \"all fine\" if true\n"));
        try
        {
            using var policy = LoadOf(allowing);

            var unreadable = policy.Decide(Allowed, PolicyClis.Copilot, "apply_patch", JsonSerializer.SerializeToElement("not a patch"), "s");
            var readable = policy.Decide(Allowed, PolicyClis.Copilot, "apply_patch", JsonSerializer.SerializeToElement("*** Update File: a.cs\n"), "s");

            Assert.Equal(DecisionOutcome.Ask, unreadable.Outcome!.Outcome);
            Assert.Equal(LocalPolicy.PatchTargetsReason, unreadable.Outcome.Reason);
            Assert.NotEqual(LocalPolicy.PatchTargetsReason, readable.Outcome?.Reason, StringComparer.Ordinal);
        }
        finally
        {
            RegoPolicyTestSupport.Delete(allowing);
        }
    }

    [Fact]
    public void A_deny_of_the_policy_stays_a_deny_for_a_command_the_parser_cannot_read()
    {
        var denying = RegoPolicyTestSupport.Folder(("p/deny.rego", "package sentinel\nimport rego.v1\ndeny contains \"no shell\" if input.kind == \"shell\"\n"));
        try
        {
            using var policy = LoadOf(denying);

            var output = policy.Decide(Allowed, PolicyClis.ClaudeCode, "Bash", Json("""{"command":"echo $(whoami)"}"""), "s");

            Assert.Equal(DecisionOutcome.Deny, output.Outcome!.Outcome);
            Assert.Equal("no shell", output.Reason);
        }
        finally
        {
            RegoPolicyTestSupport.Delete(denying);
        }
    }

    [Fact]
    public void A_call_nobody_has_an_opinion_on_leaves_the_output_of_the_other_checks_as_it_is()
    {
        using var policy = Load();

        var output = policy.Decide(Allowed, PolicyClis.ClaudeCode, "Bash", Json("""{"command":"make test"}"""), "s");

        Assert.Same(Allowed, output);
    }

    [Fact]
    public void The_strictest_of_the_policy_and_the_other_checks_wins_in_both_directions()
    {
        using var policy = Load();
        var detectorBlock = new HookOutput { Decision = HookDecision.Block, Reason = "SEC-01 High: injection" };
        var detectorWarn = new HookOutput { Decision = HookDecision.Warn, Reason = "SEC-02 Medium: odd" };

        var blockBeatsAllow = policy.Decide(detectorBlock, PolicyClis.ClaudeCode, "Bash", Json("""{"command":"ls"}"""), "s");
        var policyDenyBeatsWarn = policy.Decide(detectorWarn, PolicyClis.ClaudeCode, "Bash", Json("""{"command":"rm -rf x"}"""), "s");
        var bothDeny = policy.Decide(detectorBlock, PolicyClis.ClaudeCode, "Bash", Json("""{"command":"rm -rf x"}"""), "s");

        Assert.Equal(HookDecision.Block, blockBeatsAllow.Decision);
        Assert.Equal("SEC-01 High: injection", blockBeatsAllow.Reason);
        Assert.Equal(LocalPolicy.ChecksSource, Assert.Single(blockBeatsAllow.Outcome!.Sources));
        Assert.Equal("recursive delete", policyDenyBeatsWarn.Reason);
        Assert.Equal("SEC-01 High: injection; recursive delete", bothDeny.Reason);
        Assert.Equal([LocalPolicy.ChecksSource, "policy:org-baseline,team-guidance"], bothDeny.Outcome!.Sources);
    }

    [Fact]
    public void A_policy_edit_gives_a_new_version()
    {
        using var first = Load();
        var edited = RegoPolicyTestSupport.Folder(("org-baseline/baseline.rego", RegoPolicyTestSupport.Baseline + "\n# edited\n"), ("team-guidance/team.rego", RegoPolicyTestSupport.Guidance));
        try
        {
            using var second = LoadOf(edited);

            Assert.NotEqual(first.Version, second.Version, StringComparer.Ordinal);
        }
        finally
        {
            RegoPolicyTestSupport.Delete(edited);
        }
    }

    [Fact]
    public async Task The_hook_blocks_the_call_shows_the_agent_the_reason_and_audits_the_decision_with_its_version()
    {
        RegoPolicyTestSupport.Prime(_folder);
        var db = Path.Combine(_work, "audit.db");
        using var env = new EnvironmentScope(
            (LocalPolicy.FolderVariable, _folder), ("SENTINEL_HOOK_POLICY_CACHE_DIR", RegoPolicyTestSupport.SharedCache),
            (HookAuditTestSupport.SqliteVar, db), ("SENTINEL_HOOK_AUDIT_NDJSON", null));
        var stdout = new StringWriter();
        var stderr = new StringWriter();

        var exit = await AI.Sentinel.ClaudeCode.Cli.Program.RunAsync(
            ["pre-tool-use"], new StringReader("""{"session_id":"cc-654","tool_name":"Bash","tool_input":{"command":"rm -rf build"}}"""),
            stdout, stderr, new ExactMatchEmbeddingGenerator());

        Assert.Equal(2, exit);
        Assert.Contains("recursive delete", stderr.ToString(), StringComparison.Ordinal);
        var (entries, intact) = await HookAuditTestSupport.ReadAsync(db);
        Assert.True(intact);
        var entry = Assert.Single(entries, e => string.Equals(e.DetectorId, OutcomeAudit.DetectorId, StringComparison.Ordinal));
        Assert.StartsWith("deny: recursive delete; sources=policy:org-baseline,team-guidance; policy=", entry.Summary, StringComparison.Ordinal);
        Assert.Equal("cc-654", entry.SessionId);
        using var policy = Load();
        Assert.Contains($"policy={policy.Version};", entry.Summary, StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_copilot_hook_blocks_the_call_and_the_claude_hook_asks_where_it_can()
    {
        RegoPolicyTestSupport.Prime(_folder);
        using var env = new EnvironmentScope(
            (LocalPolicy.FolderVariable, _folder), ("SENTINEL_HOOK_POLICY_CACHE_DIR", RegoPolicyTestSupport.SharedCache),
            (HookAuditTestSupport.SqliteVar, "off"), ("SENTINEL_HOOK_HEADLESS", null));

        var copilotErr = new StringWriter();
        var copilot = await AI.Sentinel.Copilot.Cli.Program.RunAsync(
            ["pre-tool-use"], new StringReader("""{"sessionId":"c-1","toolName":"bash","toolArgs":"{\"command\":\"rm -rf x\"}"}"""),
            new StringWriter(), copilotErr, new ExactMatchEmbeddingGenerator());
        var claudeOut = new StringWriter();
        var claude = await AI.Sentinel.ClaudeCode.Cli.Program.RunAsync(
            ["pre-tool-use"], new StringReader("""{"session_id":"cc-1","tool_name":"Bash","tool_input":{"command":"git push"}}"""),
            claudeOut, new StringWriter(), new ExactMatchEmbeddingGenerator());

        Assert.Equal(2, copilot);
        Assert.Contains("recursive delete", copilotErr.ToString(), StringComparison.Ordinal);
        Assert.Equal(0, claude);
        Assert.Contains("\"permissionDecision\":\"ask\"", claudeOut.ToString(), StringComparison.Ordinal);
    }

    /// <summary>The hook as its own process, the way Claude Code runs it: with an empty cache the first call compiles the
    /// policy in a child process of the hook and blocks on it, and the second call finds the module in the cache.</summary>
    [Fact]
    public async Task The_hook_process_compiles_an_uncached_policy_in_a_child_process_and_then_uses_the_cache()
    {
        var cache = Path.Combine(_work, "process-cache");
        const string Json = """{"session_id":"cc-654","tool_name":"Bash","tool_input":{"command":"rm -rf build"}}""";

        var cold = await RegoPolicyTestSupport.RunHookProcessAsync(_folder, cache, Json);
        var files = Directory.GetFiles(cache).Select(Path.GetFileName).Order(StringComparer.Ordinal).ToList();
        var warm = await RegoPolicyTestSupport.RunHookProcessAsync(_folder, cache, Json);

        Assert.Equal(2, cold.Exit);
        Assert.Contains("recursive delete", cold.Stderr, StringComparison.Ordinal);
        Assert.Equal(2, files.Count);
        Assert.Equal(2, warm.Exit);
        Assert.Contains("recursive delete", warm.Stderr, StringComparison.Ordinal);
        Assert.Equal(files, Directory.GetFiles(cache).Select(Path.GetFileName).Order(StringComparer.Ordinal).ToList());
    }

    [Fact]
    public async Task The_hook_without_a_policy_folder_acts_as_it_did_before()
    {
        using var env = new EnvironmentScope((LocalPolicy.FolderVariable, null), (HookAuditTestSupport.SqliteVar, "off"));
        var stdout = new StringWriter();

        var exit = await AI.Sentinel.ClaudeCode.Cli.Program.RunAsync(
            ["pre-tool-use"], new StringReader("""{"session_id":"cc-1","tool_name":"Bash","tool_input":{"command":"rm -rf build"}}"""),
            stdout, new StringWriter(), new ExactMatchEmbeddingGenerator());

        Assert.Equal(0, exit);
        Assert.Equal("{}", stdout.ToString());
    }

    /// <summary>The whole decision of a hook process stays within 50 ms per call: the policy is loaded from the cache as a new
    /// process does it, the input is built, the policy is evaluated and the outcomes are combined. The first call after a
    /// policy change compiles, which is outside the per-call budget.</summary>
    [Fact]
    public void The_whole_decision_from_input_to_combined_outcome_stays_within_50_ms_with_the_module_cached()
    {
        var input = Json("""{"command":"cat a | grep b && git push origin main"}""");
        using (var warm = Load())
        {
            warm.Decide(Allowed, PolicyClis.ClaudeCode, "Bash", input, "s");
        }

        var millis = new List<double>();
        for (var i = 0; i < 40; i++)
        {
            var watch = Stopwatch.StartNew();
            using var policy = Load();
            policy.FindingSink("SEC-02", "low");
            var output = policy.Decide(Allowed, PolicyClis.ClaudeCode, "Bash", input, "s");
            watch.Stop();
            Assert.Equal(DecisionOutcome.Ask, output.Outcome!.Outcome);
            millis.Add(watch.Elapsed.TotalMilliseconds);
        }

        millis.Sort();
        var p95 = millis[(int)Math.Ceiling(millis.Count * 0.95) - 1];
        Assert.True(p95 < 50, $"p95 {p95:F1} ms, p50 {millis[millis.Count / 2]:F1} ms, max {millis[^1]:F1} ms");
    }
}
