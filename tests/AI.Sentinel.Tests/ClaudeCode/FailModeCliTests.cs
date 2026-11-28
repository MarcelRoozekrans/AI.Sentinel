using AI.Sentinel.ClaudeCode.Cli;
using AI.Sentinel.ClaudeCode.Policy;
using AI.Sentinel.Profiles;
using AI.Sentinel.Tests.Helpers;
using Xunit;
using CopilotProgram = AI.Sentinel.Copilot.Cli.Program;

namespace AI.Sentinel.Tests.ClaudeCode;

/// <summary>The fail mode of #673 through both hook CLIs, with the context handed in, as a test may. The context the hooks build from
/// the signed profiles in the state folder (#729) is tested end to end in <see cref="ServerProfileCliTests"/>.</summary>
[Collection("NonParallel")]
public class FailModeCliTests : IDisposable
{
    private readonly string _dir = HookAuditTestSupport.NewTempDir();
    private readonly string? _prevSqlite = Environment.GetEnvironmentVariable(HookAuditTestSupport.SqliteVar);
    private readonly string? _prevConfig = Environment.GetEnvironmentVariable("SENTINEL_APPROVAL_CONFIG");

    public FailModeCliTests() => Environment.SetEnvironmentVariable(HookAuditTestSupport.SqliteVar, "off");

    public void Dispose()
    {
        Environment.SetEnvironmentVariable(HookAuditTestSupport.SqliteVar, _prevSqlite);
        Environment.SetEnvironmentVariable("SENTINEL_APPROVAL_CONFIG", _prevConfig);
        HookAuditTestSupport.DeleteDir(_dir);
        GC.SuppressFinalize(this);
    }

    private static string Claude(string tool, string input) => $$"""{"session_id":"fm","tool_name":"{{tool}}","tool_input":{{input}}}""";

    private static string InRepository() => Path.Combine(Directory.GetCurrentDirectory(), "README.md").Replace("\\", "\\\\", StringComparison.Ordinal);

    private static async Task<(int Exit, string Stdout, string Stderr)> RunClaudeAsync(string json, FailModeContext? failMode)
    {
        var stdout = new StringWriter();
        var stderr = new StringWriter();
        var exit = await AI.Sentinel.ClaudeCode.Cli.Program.RunAsync(
            ["pre-tool-use"], new StringReader(json), stdout, stderr, new ExactMatchEmbeddingGenerator(), reviewer: null, policyCompilers: null,
            residentStart: null, failMode: failMode);
        return (exit, stdout.ToString(), stderr.ToString());
    }

    [Fact]
    public async Task A_server_without_a_profile_denies_a_shell_call_and_asks_the_developer_to_sign_in()
    {
        var (exit, stdout, stderr) = await RunClaudeAsync(Claude("Bash", """{"command":"ls"}"""), FailModeContext.NotSignedIn);

        Assert.Equal(2, exit);
        Assert.Empty(stdout);
        Assert.Contains("Sign in", stderr, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_server_without_a_profile_still_allows_a_read_inside_the_repository()
    {
        var (exit, _, stderr) = await RunClaudeAsync(Claude("Read", $$"""{"file_path":"{{InRepository()}}"}"""), FailModeContext.NotSignedIn);

        Assert.Equal(0, exit);
        Assert.Empty(stderr);
    }

    [Fact]
    public async Task With_fail_mode_ask_a_call_without_a_usable_profile_asks_on_stdout()
    {
        var expired = FailModeContext.From(ProfileVerification.Rejected(ProfileRejection.Expired, ProfileFailModes.Ask));

        var (exit, stdout, _) = await RunClaudeAsync(Claude("Bash", """{"command":"ls"}"""), expired);

        Assert.Equal(0, exit);
        Assert.Contains("\"permissionDecision\":\"ask\"", stdout, StringComparison.Ordinal);
    }

    [Fact]
    public async Task With_no_server_configured_the_hook_behaves_as_before()
    {
        var (exit, stdout, stderr) = await RunClaudeAsync(Claude("Bash", """{"command":"ls"}"""), FailModeContext.NoServer);
        var (plainExit, plainStdout, plainStderr) = await RunClaudeAsync(Claude("Bash", """{"command":"ls"}"""), failMode: null);

        Assert.Equal((plainExit, plainStdout, plainStderr), (exit, stdout, stderr));
        Assert.Equal(0, exit);
    }

    [Fact]
    public async Task An_internal_error_in_the_hook_still_fails_closed_whatever_the_fail_mode()
    {
        var path = Path.Combine(_dir, "approvals.json");
        File.WriteAllText(path, "{ not json");
        Environment.SetEnvironmentVariable("SENTINEL_APPROVAL_CONFIG", path);
        var expired = FailModeContext.From(ProfileVerification.Rejected(ProfileRejection.Expired, ProfileFailModes.Ask));

        var (exit, _, stderr) = await RunClaudeAsync(Claude("Read", $$"""{"file_path":"{{InRepository()}}"}"""), expired);

        Assert.Equal(2, exit);
        Assert.Contains("Sentinel internal error", stderr, StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_copilot_hook_denies_the_same_call_and_reads_inside_the_repository_stay_allowed()
    {
        var shell = new StringWriter();
        var shellErr = new StringWriter();
        var read = new StringWriter();
        var readErr = new StringWriter();
        var bash = """{"sessionId":"fm","toolName":"bash","toolArgs":{"command":"ls"}}""";
        var view = $$$"""{"sessionId":"fm","toolName":"view","toolArgs":{"path":"{{{InRepository()}}}"}}""";

        await CopilotProgram.RunAsync(
            ["pre-tool-use"], new StringReader(bash), shell, shellErr, new ExactMatchEmbeddingGenerator(), reviewer: null, policyCompilers: null,
            residentStart: null, failMode: FailModeContext.NotSignedIn);
        var allowed = await CopilotProgram.RunAsync(
            ["pre-tool-use"], new StringReader(view), read, readErr, new ExactMatchEmbeddingGenerator(), reviewer: null, policyCompilers: null,
            residentStart: null, failMode: FailModeContext.NotSignedIn);

        Assert.Contains("\"decision\":\"Block\"", shell.ToString() + shellErr.ToString(), StringComparison.Ordinal);
        Assert.Contains("Sign in", shell.ToString() + shellErr.ToString(), StringComparison.Ordinal);
        Assert.Equal(0, allowed);
        Assert.DoesNotContain("Block", read.ToString() + readErr.ToString(), StringComparison.Ordinal);
    }
}
