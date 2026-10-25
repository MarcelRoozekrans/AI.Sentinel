using Xunit;
using AI.Sentinel.Authorization;
using AI.Sentinel.Copilot.Cli;
using AI.Sentinel.Tests.Helpers;
using Microsoft.Extensions.AI;

namespace AI.Sentinel.Tests.Copilot;

/// <summary>When the hook itself fails on PreToolUse it blocks the tool call (exit 2) with the error as the reason;
/// on every other event it exits 1, which the host does not treat as a block (#478).</summary>
[Collection("NonParallel")]
public class CopilotHookCliFailClosedTests : IDisposable
{
    private const string PreToolUse = """{"sessionId":"cp-478","toolName":"bash","toolArgs":{"command":"ls"}}""";
    private const string Prompt = """{"sessionId":"cp-478","prompt":"hello"}""";

    private readonly string _dir = HookAuditTestSupport.NewTempDir();
    private readonly string? _prevSqlite = Environment.GetEnvironmentVariable(HookAuditTestSupport.SqliteVar);
    private readonly string? _prevConfig = Environment.GetEnvironmentVariable("SENTINEL_APPROVAL_CONFIG");

    public CopilotHookCliFailClosedTests() =>
        Environment.SetEnvironmentVariable(HookAuditTestSupport.SqliteVar, "off");

    public void Dispose()
    {
        Environment.SetEnvironmentVariable(HookAuditTestSupport.SqliteVar, _prevSqlite);
        Environment.SetEnvironmentVariable("SENTINEL_APPROVAL_CONFIG", _prevConfig);
        HookAuditTestSupport.DeleteDir(_dir);
        GC.SuppressFinalize(this);
    }

    private string UseApprovalConfig(string json)
    {
        var path = Path.Combine(_dir, "approvals.json");
        File.WriteAllText(path, json);
        Environment.SetEnvironmentVariable("SENTINEL_APPROVAL_CONFIG", path);
        return path;
    }

    private static async Task<(int Exit, string Stdout, string Stderr)> RunAsync(
        string evt, string json, IEmbeddingGenerator<string, Embedding<float>>? generator = null)
    {
        var stdout = new StringWriter();
        var stderr = new StringWriter();
        var exit = await Program.RunAsync([evt], new StringReader(json), stdout, stderr, generator ?? new FakeEmbeddingGenerator());
        return (exit, stdout.ToString(), stderr.ToString());
    }

    public static TheoryData<string> BrokenConfigs => new()
    {
        "{ not json",
        """{ "backend": "in-memory", "tools": { "bash": { "role": "Ops", "when": { "$.command": "(" } } } }""",
        """{ "backend": "in-memory", "tools": { "bash": { "role": "Ops" }, "bash": { "role": "Dba" } } }""",
    };

    [Theory]
    [MemberData(nameof(BrokenConfigs))]
    public async Task PreToolUse_BrokenApprovalConfig_BlocksWithTheError(string config)
    {
        var path = UseApprovalConfig(config);

        var (exit, stdout, stderr) = await RunAsync("pre-tool-use", PreToolUse);

        Assert.Equal(2, exit);
        Assert.Empty(stdout);
        Assert.StartsWith($"Sentinel internal error: approval config '{path}' could not be loaded: ", stderr, StringComparison.Ordinal);
    }

    [Fact]
    public async Task PreToolUse_MissingApprovalConfig_Blocks()
    {
        var path = Path.Combine(_dir, "missing.json");
        Environment.SetEnvironmentVariable("SENTINEL_APPROVAL_CONFIG", path);

        var (exit, _, stderr) = await RunAsync("pre-tool-use", PreToolUse);

        Assert.Equal(2, exit);
        Assert.Contains($"Sentinel internal error: approval config '{path}'", stderr, StringComparison.Ordinal);
    }

    [Theory]
    [MemberData(nameof(BrokenConfigs))]
    public async Task UserPromptSubmitted_BrokenApprovalConfig_ExitsOne(string config)
    {
        var path = UseApprovalConfig(config);

        var (exit, _, stderr) = await RunAsync("user-prompt-submitted", Prompt);

        Assert.Equal(1, exit);
        Assert.Contains($"Failed to load approval config from '{path}'", stderr, StringComparison.Ordinal);
    }

    [Fact]
    public async Task PostToolUse_BrokenApprovalConfig_ExitsOne()
    {
        UseApprovalConfig("{ not json");

        var (exit, _, _) = await RunAsync("post-tool-use", """{"sessionId":"s","toolName":"bash","toolArgs":{"command":"ls"},"toolResult":{"resultType":"success","textResultForLlm":"ok"}}""");

        Assert.Equal(1, exit);
    }

    // The approval database cannot be opened, because its parent "directory" is a file, so building the guard throws.
    [Fact]
    public async Task PreToolUse_GuardThrows_BlocksWithTheException()
    {
        var blocker = Path.Combine(_dir, "not-a-dir");
        File.WriteAllText(blocker, "");
        var dbPath = Path.Combine(blocker, "approvals.db");
        UseApprovalConfig($$"""{ "backend": "sqlite", "databasePath": {{System.Text.Json.JsonSerializer.Serialize(dbPath)}}, "tools": { "bash": { "role": "Ops" } } }""");

        var (exit, _, stderr) = await RunAsync("pre-tool-use", PreToolUse);

        Assert.Equal(2, exit);
        Assert.StartsWith("Sentinel internal error: ", stderr, StringComparison.Ordinal);
        Assert.DoesNotContain("approval config", stderr, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("not json")]
    [InlineData("")]
    public async Task PreToolUse_MalformedStdin_Blocks(string json)
    {
        var (exit, _, stderr) = await RunAsync("pre-tool-use", json);

        Assert.Equal(2, exit);
        Assert.StartsWith("Error: ", stderr, StringComparison.Ordinal);
    }

    [Fact]
    public async Task PostToolUse_MalformedStdin_ExitsOne()
    {
        var (exit, _, _) = await RunAsync("post-tool-use", "not json");

        Assert.Equal(1, exit);
    }

    // Detectors fail open: the pipeline skips a detector that throws and reports it, and the tool still runs.
    [Fact]
    public async Task PreToolUse_DetectorThrows_AllowsAndReports()
    {
        var (exit, _, stderr) = await RunAsync("pre-tool-use", PreToolUse, new ThrowingEmbeddingGenerator());

        Assert.Equal(0, exit);
        Assert.Contains("failed and was skipped for this scan", stderr, StringComparison.Ordinal);
        Assert.DoesNotContain("Sentinel internal error", stderr, StringComparison.Ordinal);
    }

    [Fact]
    public async Task PreToolUse_BrokenApprovalConfig_RecordsAnInternalErrorDeny()
    {
        var db = Path.Combine(_dir, "audit.db");
        Environment.SetEnvironmentVariable(HookAuditTestSupport.SqliteVar, db);
        UseApprovalConfig("{ not json");

        var (exit, _, _) = await RunAsync("pre-tool-use", PreToolUse);

        Assert.Equal(2, exit);
        var (entries, intact) = await HookAuditTestSupport.ReadAsync(db);
        Assert.True(intact);
        var entry = Assert.Single(entries);
        Assert.Equal(SentinelDenyCodes.InternalError, entry.PolicyCode);
        Assert.Equal("cp-478", entry.SessionId);
        Assert.Equal("copilot", entry.Source);
        Assert.Contains("'bash'", entry.Summary, StringComparison.Ordinal);
    }

    private sealed class ThrowingEmbeddingGenerator : IEmbeddingGenerator<string, Embedding<float>>
    {
        public EmbeddingGeneratorMetadata Metadata { get; } = new("throwing", null, null, 256);

        public Task<GeneratedEmbeddings<Embedding<float>>> GenerateAsync(
            IEnumerable<string> values,
            EmbeddingGenerationOptions? options = null,
            CancellationToken cancellationToken = default)
            => throw new InvalidOperationException("intentional test failure");

        public object? GetService(Type serviceType, object? key = null) => null;
        public void Dispose() { }
    }
}
