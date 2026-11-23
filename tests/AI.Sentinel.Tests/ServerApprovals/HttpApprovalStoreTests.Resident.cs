using AI.Sentinel.Approvals;
using AI.Sentinel.ClaudeCode.Cli;
using AI.Sentinel.ClaudeCode.Resident;
using AI.Sentinel.ClaudeCode.ServerApprovals;
using AI.Sentinel.Tests.ClaudeCode;
using AI.Sentinel.Tests.Helpers;
using System.Net.Http.Json;
using AI.Sentinel.Tests.ClaudeCode.Resident;
using Xunit;

namespace AI.Sentinel.Tests.ServerApprovals;

// The hook side: the resident process that asks the server, and the hook that has no way to ask.
public sealed partial class HttpApprovalStoreTests
{
    private static ApprovalChannelReply Reply(IApprovalChannel channel, string request) =>
        channel.GetAsync(request, Ct).GetAwaiter().GetResult();

    [Fact]
    public async Task The_hook_asks_the_server_through_the_resident_process_and_acts_on_the_decision()
    {
        await StartAsync();
        var dir = ResidentTestSupport.NewDir();
        try
        {
            await using var resident = new HostedResident(dir, approvals: new ApprovalServerClient(Dave()));
            await resident.WaitUntilListeningAsync();
            var hook = HookOf(new ResidentApprovalChannel(new ResidentClient(resident.Settings)));

            var pending = await OpenAsync(hook);
            Assert.True(pending.IsNew);
            Assert.Equal("dave", Assert.Single((await Lena().GetFromJsonAsync(Path, ApprovalWireJsonContext.Default.ApprovalListWire, Ct))!.Requests).Requester);
            await DecideAsync(Lena(), pending.RequestId, "approve");

            Assert.IsType<ApprovalState.Active>(await hook.EnsureRequestAsync(new Caller("hook"), Spec(), Context(), Ct));
            Assert.Equal(ApprovalChannelStatus.Ok, Reply(new ResidentApprovalChannel(new ResidentClient(resident.Settings)), pending.RequestId).Status);
            Assert.Equal(ApprovalChannelStatus.NotFound, Reply(new ResidentApprovalChannel(new ResidentClient(resident.Settings)), "req-unknown").Status);
        }
        finally
        {
            ResidentTestSupport.Delete(dir);
        }
    }

    [Fact]
    public async Task A_resident_process_that_is_not_there_is_an_unreachable_server()
    {
        var dir = ResidentTestSupport.NewDir();
        try
        {
            var settings = new ResidentSettings(dir, TimeSpan.FromMinutes(1), TimeSpan.FromMilliseconds(50));
            var state = await HookOf(new ResidentApprovalChannel(new ResidentClient(settings))).EnsureRequestAsync(new Caller("hook"), Spec(), Context(), Ct);

            Assert.Equal(HttpApprovalStore.UnreachableReason, Assert.IsType<ApprovalState.Denied>(state).Reason);
        }
        finally
        {
            ResidentTestSupport.Delete(dir);
        }
    }

    [Fact]
    public async Task A_resident_process_with_no_server_says_so_and_a_server_that_is_down_is_unreachable_through_it()
    {
        var dir = ResidentTestSupport.NewDir();
        try
        {
            await using var bare = new HostedResident(dir);
            await bare.WaitUntilListeningAsync();
            var state = await HookOf(new ResidentApprovalChannel(new ResidentClient(bare.Settings))).EnsureRequestAsync(new Caller("hook"), Spec(), Context(), Ct);
            Assert.Equal(HttpApprovalStore.OffReason, Assert.IsType<ApprovalState.Denied>(state).Reason);
        }
        finally
        {
            ResidentTestSupport.Delete(dir);
        }

        dir = ResidentTestSupport.NewDir();
        try
        {
            using var down = new HttpClient(new ThrowingHandler()) { BaseAddress = new Uri("https://sentinel.example.com/") };
            await using var resident = new HostedResident(dir, approvals: new ApprovalServerClient(down));
            await resident.WaitUntilListeningAsync();
            var state = await HookOf(new ResidentApprovalChannel(new ResidentClient(resident.Settings))).EnsureRequestAsync(new Caller("hook"), Spec(), Context(), Ct);
            Assert.Equal(HttpApprovalStore.UnreachableReason, Assert.IsType<ApprovalState.Denied>(state).Reason);
        }
        finally
        {
            ResidentTestSupport.Delete(dir);
        }
    }

    private const string HttpConfig = """{ "backend": "http", "tools": { "Bash": { "role": "Ops" } } }""";

    private static async Task<(int Exit, string Stderr)> PreToolUseAsync()
    {
        var stdin = new StringReader("""{"session_id":"s","tool_name":"Bash","tool_input":{"command":"kubectl apply -f prod.yaml"}}""");
        var stderr = new StringWriter();
        var exit = await Program.RunAsync(["pre-tool-use"], stdin, new StringWriter(), stderr, embeddingGenerator: null);
        return (exit, stderr.ToString());
    }

    private static IDisposable Environment_(string config, string? residentDir)
    {
        var dir = HookAuditTestSupport.NewTempDir();
        var path = System.IO.Path.Combine(dir, "approvals.json");
        File.WriteAllText(path, config);
        var previous = new Dictionary<string, string?>(StringComparer.Ordinal);
        foreach (var (name, value) in new Dictionary<string, string?>(StringComparer.Ordinal)
        {
            ["SENTINEL_APPROVAL_CONFIG"] = path,
            [HookAuditTestSupport.SqliteVar] = "off",
            ["SENTINEL_HOOK_RESIDENT"] = residentDir is null ? null : "on",
            ["SENTINEL_HOOK_RESIDENT_DIR"] = residentDir,
        })
        {
            previous[name] = Environment.GetEnvironmentVariable(name);
            Environment.SetEnvironmentVariable(name, value);
        }

        return new Restore(dir, previous);
    }

    private sealed class Restore(string dir, Dictionary<string, string?> previous) : IDisposable
    {
        public void Dispose()
        {
            foreach (var (name, value) in previous)
            {
                Environment.SetEnvironmentVariable(name, value);
            }

            HookAuditTestSupport.DeleteDir(dir);
        }
    }

    [Fact]
    public async Task The_hook_with_the_http_backend_and_no_resident_process_blocks_the_call_as_unreachable()
    {
        using var _ = Environment_(HttpConfig, residentDir: null);

        var (exit, stderr) = await PreToolUseAsync();

        Assert.Equal(2, exit);
        Assert.Contains("unreachable", stderr, StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_hook_with_the_http_backend_blocks_until_the_server_approves_and_then_lets_the_retry_through()
    {
        await StartAsync();
        var dir = ResidentTestSupport.NewDir();
        try
        {
            await using var resident = new HostedResident(dir, approvals: new ApprovalServerClient(Dave()));
            await resident.WaitUntilListeningAsync();
            using var _ = Environment_(HttpConfig, residentDir: dir);

            var (first, firstError) = await PreToolUseAsync();
            Assert.Equal(2, first);
            Assert.Contains("Approval required to invoke tool 'Bash'", firstError, StringComparison.Ordinal);

            var request = Assert.Single((await Root().GetFromJsonAsync(Path, ApprovalWireJsonContext.Default.ApprovalListWire, Ct))!.Requests);
            Assert.Equal("Bash", request.Tool);
            Assert.Contains("kubectl apply", request.Args!.Value.GetProperty("command").GetString(), StringComparison.Ordinal);
            await DecideAsync(Root(), request.Id, "approve");

            var (second, secondError) = await PreToolUseAsync();
            Assert.Equal(0, second);
            Assert.DoesNotContain("Approval required", secondError, StringComparison.Ordinal);
        }
        finally
        {
            ResidentTestSupport.Delete(dir);
        }
    }

    [Fact]
    public async Task The_other_hook_tools_refuse_the_http_backend_instead_of_serving_it_from_memory()
    {
        using var _ = Environment_(HttpConfig, residentDir: null);
        var stderr = new StringWriter();

        var (provider, _, _, _, configError) = await AI.Sentinel.Mcp.Cli.ProxyCommand.BuildAuthorizationStackAsync(stderr);

        Assert.True(configError);
        Assert.Null(provider);
        Assert.Contains("only sentinel-hook supports", stderr.ToString(), StringComparison.Ordinal);
        Assert.Throws<InvalidOperationException>(() => AI.Sentinel.Copilot.Cli.Program.BuildProvider(
            embeddingGenerator: null,
            approvalConfig: AI.Sentinel.Approvals.Configuration.ApprovalConfigLoader.Parse(System.Text.Json.JsonDocument.Parse(HttpConfig).RootElement)));
    }
}
