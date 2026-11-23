using System.Text.Json;
using AI.Sentinel.Authorization;
using AI.Sentinel.ClaudeCode;
using AI.Sentinel.ClaudeCode.Policy;
using AI.Sentinel.ClaudeCode.Policy.Rego;
using AI.Sentinel.Tests.Helpers;
using Xunit;

namespace AI.Sentinel.Tests.ClaudeCode.Policy;

/// <summary>A policy folder that cannot be read, compiled or loaded blocks PreToolUse with an internal-error reason, and a
/// builtin that reaches outside the process is refused when compiled and, if a module slipped through, when it is met (#654).
/// Nothing here fails open.</summary>
[Collection("NonParallel")]
public class RegoPolicyLoadFailureTests : IDisposable
{
    private const string PreToolUse = """{"session_id":"cc-654","tool_name":"Bash","tool_input":{"command":"ls"}}""";

    private readonly List<string> _folders = [];
    private readonly string _work = HookAuditTestSupport.NewTempDir();

    public void Dispose()
    {
        _folders.ForEach(RegoPolicyTestSupport.Delete);
        HookAuditTestSupport.DeleteDir(_work);
        GC.SuppressFinalize(this);
    }

    private string Folder(params (string Path, string Text)[] files)
    {
        var folder = RegoPolicyTestSupport.Folder(files);
        _folders.Add(folder);
        return folder;
    }

    private static JsonElement Json(string json) => JsonDocument.Parse(json).RootElement;

    private static string Rule(string body) => "package sentinel\nimport rego.v1\n" + body + "\n";

    private async Task<(int Exit, string Stdout, string Stderr, string Db)> RunClaudeAsync(
        string folder, string json = PreToolUse, string evt = "pre-tool-use", string? cache = null, IReadOnlyList<IRegoCompiler>? compilers = null)
    {
        var db = Path.Combine(_work, Guid.NewGuid().ToString("N") + ".db");
        using var env = new EnvironmentScope(
            (LocalPolicy.FolderVariable, folder), ("SENTINEL_HOOK_POLICY_CACHE_DIR", cache ?? RegoPolicyTestSupport.SharedCache),
            (HookAuditTestSupport.SqliteVar, db), ("SENTINEL_HOOK_AUDIT_NDJSON", null));
        var stdout = new StringWriter();
        var stderr = new StringWriter();
        var exit = await AI.Sentinel.ClaudeCode.Cli.Program.RunAsync(
            [evt], new StringReader(json), stdout, stderr, new ExactMatchEmbeddingGenerator(), reviewer: null, policyCompilers: compilers);
        return (exit, stdout.ToString(), stderr.ToString(), db);
    }

    private static async Task AssertInternalErrorEntryAsync(string db)
    {
        var (entries, intact) = await HookAuditTestSupport.ReadAsync(db);
        Assert.True(intact);
        var entry = Assert.Single(entries);
        Assert.Equal(SentinelDenyCodes.InternalError, entry.PolicyCode);
        Assert.Contains("policy 'sentinel-internal'", entry.Summary, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_folder_that_does_not_exist_blocks_PreToolUse_as_an_internal_error_and_audits_it()
    {
        var folder = Path.Combine(_work, "missing");

        var (exit, stdout, stderr, db) = await RunClaudeAsync(folder);

        Assert.Equal(2, exit);
        Assert.Empty(stdout);
        Assert.StartsWith($"Sentinel internal error: policy '{folder}' could not be evaluated: ", stderr, StringComparison.Ordinal);
        await AssertInternalErrorEntryAsync(db);
    }

    [Fact]
    public async Task A_folder_without_rego_files_blocks()
    {
        var (exit, _, stderr, _) = await RunClaudeAsync(Folder(("notes.txt", "no rego")));

        Assert.Equal(2, exit);
        Assert.Contains("holds no .rego file", stderr, StringComparison.Ordinal);
    }

    [Fact]
    public void A_policy_that_does_not_compile_is_not_loaded_and_the_error_is_the_compiler_message()
    {
        var folder = Folder(("p/bad.rego", Rule("deny contains \"x\" if {")));
        var cache = Path.Combine(_work, "bad-cache");
        _folders.Add(cache);

        var error = Assert.Throws<RegoCompileException>(
            () => LocalPolicy.Load(folder, RegoPolicyTestSupport.Env(cache), "/work/repo", RegoPolicyTestSupport.Compilers(new ChildProcessCompiler())));

        Assert.Contains("rego_parse_error", error.Message, StringComparison.Ordinal);
        Assert.Empty(Directory.GetFiles(cache));
    }

    /// <summary>A compiler child that crashes, hangs, fails or leaves no valid module is a load failure: the hook blocks
    /// PreToolUse, as exit code 2 with an internal-error reason. A crash in the hook process itself would be a non-blocking
    /// error to Claude Code, which runs the tool call; this is why the hook compiles in a child.</summary>
    [Theory]
    [InlineData("kill -SEGV $$", "exited with code 139")]
    [InlineData("exit 139", "exited with code 139")]
    [InlineData("exit 1", "exited with code 1")]
    [InlineData("exit 0", "wrote no valid module")]
    [InlineData("printf garbage > \"$3\"", "wrote no valid module")]
    [InlineData("sleep 30", "did not finish within")]
    public async Task A_compiler_child_that_crashes_or_fails_blocks_PreToolUse_as_an_internal_error(string script, string reason)
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), "the child is a POSIX shell script");
        var folder = Folder(("p/a.rego", Rule("allow contains \"x\" if true")));
        var cache = Path.Combine(_work, "crash-cache-" + Guid.NewGuid().ToString("N"));
        var compiler = new ChildProcessRegoCompiler("/bin/sh", ["-c", script, "sh"], timeout: TimeSpan.FromSeconds(2));

        var (exit, stdout, stderr, db) = await RunClaudeAsync(folder, cache: cache, compilers: [compiler]);

        Assert.Equal(2, exit);
        Assert.Empty(stdout);
        Assert.StartsWith($"Sentinel internal error: policy '{folder}' could not be evaluated: ", stderr, StringComparison.Ordinal);
        Assert.Contains(reason, stderr, StringComparison.Ordinal);
        await AssertInternalErrorEntryAsync(db);
        Assert.Empty(Directory.GetFiles(cache));
    }

    [Fact]
    public async Task A_compiler_child_that_crashes_blocks_the_copilot_hook_too()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), "the child is a POSIX shell script");
        var folder = Folder(("p/a.rego", Rule("allow contains \"x\" if true")));
        using var env = new EnvironmentScope(
            (LocalPolicy.FolderVariable, folder), ("SENTINEL_HOOK_POLICY_CACHE_DIR", Path.Combine(_work, "copilot-crash-cache")),
            (HookAuditTestSupport.SqliteVar, "off"));
        var stderr = new StringWriter();

        var exit = await AI.Sentinel.Copilot.Cli.Program.RunAsync(
            ["pre-tool-use"], new StringReader("""{"sessionId":"c-1","toolName":"bash","toolArgs":"{\"command\":\"ls\"}"}"""),
            new StringWriter(), stderr, new ExactMatchEmbeddingGenerator(), reviewer: null,
            policyCompilers: [new ChildProcessRegoCompiler("/bin/sh", ["-c", "kill -SEGV $$", "sh"])]);

        Assert.Equal(2, exit);
        Assert.Contains("exited with code 139", stderr.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void The_hooks_never_load_the_go_compiler_into_their_own_process()
    {
        var hook = RegoPolicy.HookCompilers();

        Assert.IsType<ChildProcessRegoCompiler>(hook[0]);
        Assert.IsType<OpaBinaryCompiler>(hook[1]);
        Assert.All(RegoPolicy.DefaultCompilers(), c => Assert.True(c is ChildProcessRegoCompiler or OpaBinaryCompiler, c.Name));
    }

    [Fact]
    public async Task The_copilot_hook_blocks_the_same_way()
    {
        var db = Path.Combine(_work, "copilot.db");
        using var env = new EnvironmentScope(
            (LocalPolicy.FolderVariable, Path.Combine(_work, "missing")), ("SENTINEL_HOOK_POLICY_CACHE_DIR", RegoPolicyTestSupport.SharedCache),
            (HookAuditTestSupport.SqliteVar, db));
        var stderr = new StringWriter();

        var exit = await AI.Sentinel.Copilot.Cli.Program.RunAsync(
            ["pre-tool-use"], new StringReader("""{"sessionId":"c-1","toolName":"bash","toolArgs":"{\"command\":\"ls\"}"}"""),
            new StringWriter(), stderr, new ExactMatchEmbeddingGenerator());

        Assert.Equal(2, exit);
        Assert.Contains("Sentinel internal error: policy", stderr.ToString(), StringComparison.Ordinal);
        await AssertInternalErrorEntryAsync(db);
    }

    [Fact]
    public async Task Other_events_do_not_read_the_policy_so_a_broken_folder_changes_nothing_there()
    {
        var (exit, _, stderr, _) = await RunClaudeAsync(
            Path.Combine(_work, "missing"), """{"session_id":"s","prompt":"hello"}""", evt: "user-prompt-submit");

        Assert.Equal(0, exit);
        Assert.DoesNotContain("policy", stderr, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("http.send({\"method\": \"get\", \"url\": \"https://example.com\"})", "http.send")]
    [InlineData("net.lookup_ip_addr(\"example.com\")", "net.lookup_ip_addr")]
    [InlineData("opa.runtime()", "opa.runtime")]
    public void A_policy_that_uses_a_builtin_reaching_outside_the_process_is_refused_when_compiled(string call, string builtin)
    {
        var folder = Folder(("p/outside.rego", Rule($"deny contains \"x\" if {{\n\t_ = {call}\n}}")));
        var cache = Path.Combine(_work, "refused-cache");
        _folders.Add(cache);

        var error = Assert.Throws<RegoCompileException>(
            () => LocalPolicy.Load(folder, RegoPolicyTestSupport.Env(cache), "/work/repo", RegoPolicyTestSupport.Compilers(new ChildProcessCompiler())));

        Assert.Contains($"{builtin}, which reaches outside the process and is refused", error.Message, StringComparison.Ordinal);
        Assert.Empty(Directory.GetFiles(cache));
    }

    [Theory]
    [InlineData("http.send({\"method\": \"get\", \"url\": input.tool})", "builtin http.send reaches outside the process and is refused")]
    [InlineData("net.lookup_ip_addr(input.tool)", "builtin net.lookup_ip_addr reaches outside the process and is refused")]
    [InlineData("opa.runtime()", "builtin opa.runtime reaches outside the process and is refused")]
    [InlineData("uuid.rfc4122(input.tool)", "builtin uuid.rfc4122 is not implemented by the host")]
    [InlineData("time.now_ns()", "builtin time.now_ns is not implemented by the host")]
    public void A_module_that_meets_such_a_builtin_at_run_time_denies_and_names_it(string call, string reason)
    {
        var folder = Folder(("p/outside.rego", Rule($"deny contains \"x\" if {{\n\t_ = {call}\n}}")));
        var cache = Path.Combine(_work, "unrestricted-cache");
        _folders.Add(cache);
        using var policy = LocalPolicy.Load(folder, RegoPolicyTestSupport.Env(cache), "/work/repo", RegoPolicyTestSupport.Compilers(new ChildProcessCompiler(unrestricted: true)));

        var output = policy.Decide(new HookOutput { Decision = HookDecision.Allow }, PolicyClis.ClaudeCode, "Bash", Json("""{"command":"ls"}"""), "s");

        Assert.Equal(HookDecision.Block, output.Decision);
        Assert.Equal(reason, output.Reason);
        Assert.StartsWith("builtin:", Assert.Single(output.Outcome!.Sources), StringComparison.Ordinal);
    }

    [Fact]
    public void A_policy_that_calls_no_such_builtin_is_not_refused_by_the_module_of_the_rules_that_ran()
    {
        var folder = Folder(("p/ok.rego", Rule("deny contains \"x\" if {\n\tinput.tool == \"never\"\n\t_ = opa.runtime()\n}")));
        var cache = Path.Combine(_work, "unrestricted-cache-2");
        _folders.Add(cache);
        using var policy = LocalPolicy.Load(folder, RegoPolicyTestSupport.Env(cache), "/work/repo", RegoPolicyTestSupport.Compilers(new ChildProcessCompiler(unrestricted: true)));

        // The call sits behind a condition that is false, so the module never meets the builtin for this input.
        var output = policy.Decide(new HookOutput { Decision = HookDecision.Allow }, PolicyClis.ClaudeCode, "Bash", Json("""{"command":"ls"}"""), "s");

        Assert.Equal(HookDecision.Allow, output.Decision);
    }

    [Fact]
    public void A_policy_that_redefines_a_rule_of_the_host_fails_when_it_runs_and_the_hook_blocks_on_it()
    {
        var folder = Folder(("p/clash.rego", Rule("decision := {\"outcome\": \"allow\", \"reasons\": [\"mine\"]}")));
        var cache = Path.Combine(_work, "clash-cache");
        _folders.Add(cache);
        using var policy = LocalPolicy.Load(folder, RegoPolicyTestSupport.Env(cache), "/work/repo", RegoPolicyTestSupport.Compilers(new ChildProcessCompiler()));

        // OPA reports two different values for one complete rule as a conflict while evaluating, so the call fails and
        // the hooks turn the exception into an internal-error block. It is never an allow.
        Assert.ThrowsAny<Exception>(
            () => policy.Decide(new HookOutput { Decision = HookDecision.Allow }, PolicyClis.ClaudeCode, "Bash", Json("""{"command":"ls"}"""), "s"));
    }

    [Fact]
    public async Task A_policy_that_fails_while_it_runs_blocks_the_call_as_an_internal_error()
    {
        var folder = Folder(("p/clash.rego", Rule("decision := {\"outcome\": \"allow\", \"reasons\": [\"mine\"]}")));
        RegoPolicyTestSupport.Prime(folder);

        var (exit, stdout, stderr, db) = await RunClaudeAsync(folder);

        Assert.Equal(2, exit);
        Assert.Empty(stdout);
        Assert.StartsWith("Sentinel internal error: ", stderr, StringComparison.Ordinal);
        await AssertInternalErrorEntryAsync(db);
    }

    [Fact]
    public void A_folder_that_uses_the_reserved_host_folder_is_refused()
    {
        var folder = Folder(("_sentinel_host/mine.rego", Rule("allow contains \"x\" if true")));

        var error = Assert.Throws<InvalidDataException>(() => PolicySources.Load(folder));

        Assert.Contains("reserved", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_machine_with_no_compiler_cannot_load_an_uncached_policy_and_says_why()
    {
        var folder = Folder(("p/a.rego", Rule("allow contains \"x\" if true")));
        var cache = Path.Combine(_work, "no-compiler-cache");
        _folders.Add(cache);

        var error = Assert.Throws<InvalidOperationException>(
            () => LocalPolicy.Load(folder, RegoPolicyTestSupport.Env(cache), "/work/repo", [new MissingCompiler()]));

        Assert.Contains("no compiler can run here", error.Message, StringComparison.Ordinal);
        Assert.Contains("missing: no compiler on this machine", error.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("linux-musl-x64")]
    [InlineData("linux-musl-arm64")]
    public void A_platform_without_the_wasmtime_library_is_named(string runtimeIdentifier)
    {
        var gap = RegoPolicy.PlatformGap(runtimeIdentifier);

        Assert.NotNull(gap);
        Assert.Contains(runtimeIdentifier, gap, StringComparison.Ordinal);
        Assert.Contains("Wasmtime", gap, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("linux-x64")]
    [InlineData("linux-arm64")]
    [InlineData("osx-arm64")]
    [InlineData("win-x64")]
    public void A_platform_with_the_wasmtime_library_has_no_gap(string runtimeIdentifier) =>
        Assert.Null(RegoPolicy.PlatformGap(runtimeIdentifier));
}
