using Xunit;
using AI.Sentinel.Audit;
using AI.Sentinel.Authorization;
using AI.Sentinel.ClaudeCode.Cli;
using AI.Sentinel.Tests.Helpers;
using Microsoft.Extensions.AI;

namespace AI.Sentinel.Tests.ClaudeCode;

/// <summary>When the hook itself fails on PreToolUse it blocks the tool call (exit 2) with the error as the reason;
/// on every other event it exits 1, which the host does not treat as a block (#478).</summary>
[Collection("NonParallel")]
public class HookCliFailClosedTests : IDisposable
{
    private const string PreToolUse = """{"session_id":"cc-478","tool_name":"Bash","tool_input":{"command":"ls"}}""";
    private const string NoToolName = """{"session_id":"cc-478","tool_input":{"command":"ls"}}""";
    private const string Prompt = """{"session_id":"cc-478","prompt":"hello"}""";

    private readonly string _dir = HookAuditTestSupport.NewTempDir();
    private readonly string? _prevSqlite = Environment.GetEnvironmentVariable(HookAuditTestSupport.SqliteVar);
    private readonly string? _prevConfig = Environment.GetEnvironmentVariable("SENTINEL_APPROVAL_CONFIG");
    private readonly string? _prevVerbose = Environment.GetEnvironmentVariable("SENTINEL_HOOK_VERBOSE");

    public HookCliFailClosedTests() =>
        Environment.SetEnvironmentVariable(HookAuditTestSupport.SqliteVar, "off");

    public void Dispose()
    {
        Environment.SetEnvironmentVariable(HookAuditTestSupport.SqliteVar, _prevSqlite);
        Environment.SetEnvironmentVariable("SENTINEL_APPROVAL_CONFIG", _prevConfig);
        Environment.SetEnvironmentVariable("SENTINEL_HOOK_VERBOSE", _prevVerbose);
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

    private string UseAuditDatabase()
    {
        var db = Path.Combine(_dir, "audit.db");
        Environment.SetEnvironmentVariable(HookAuditTestSupport.SqliteVar, db);
        return db;
    }

    /// <summary>Asserts the run recorded exactly one entry: the internal-error block.</summary>
    private static async Task<AuditEntry> AssertInternalErrorEntryAsync(string db, string toolName)
    {
        var (entries, intact) = await HookAuditTestSupport.ReadAsync(db);
        Assert.True(intact);
        var entry = Assert.Single(entries);
        Assert.Equal(SentinelDenyCodes.InternalError, entry.PolicyCode);
        Assert.Equal("claude-code", entry.Source);
        Assert.Contains($"tool '{toolName}'", entry.Summary, StringComparison.Ordinal);
        Assert.Contains("policy 'sentinel-internal'", entry.Summary, StringComparison.Ordinal);
        return entry;
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
        """{ "backend": "in-memory", "tools": { "Bash": { "role": "Ops", "when": { "$.command": "(" } } } }""",
        """{ "backend": "in-memory", "tools": { "Bash": { "role": "Ops" }, "Bash": { "role": "Dba" } } }""",
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

        var (exit, stdout, stderr) = await RunAsync("pre-tool-use", PreToolUse);

        Assert.Equal(2, exit);
        Assert.Empty(stdout);
        Assert.Contains($"Sentinel internal error: approval config '{path}'", stderr, StringComparison.Ordinal);
    }

    [Theory]
    [MemberData(nameof(BrokenConfigs))]
    public async Task UserPromptSubmit_BrokenApprovalConfig_ExitsOne(string config)
    {
        var path = UseApprovalConfig(config);

        var (exit, _, stderr) = await RunAsync("user-prompt-submit", Prompt);

        Assert.Equal(1, exit);
        Assert.Contains($"Failed to load approval config from '{path}'", stderr, StringComparison.Ordinal);
    }

    [Fact]
    public async Task PostToolUse_BrokenApprovalConfig_ExitsOne()
    {
        UseApprovalConfig("{ not json");

        var (exit, _, _) = await RunAsync("post-tool-use", """{"session_id":"s","tool_name":"Bash","tool_input":{"command":"ls"},"tool_response":{"stdout":"ok"}}""");

        Assert.Equal(1, exit);
    }

    // The approval database cannot be opened, because its parent "directory" is a file, so building the guard throws.
    [Fact]
    public async Task PreToolUse_GuardThrows_BlocksWithTheException()
    {
        var blocker = Path.Combine(_dir, "not-a-dir");
        File.WriteAllText(blocker, "");
        var dbPath = Path.Combine(blocker, "approvals.db");
        UseApprovalConfig($$"""{ "backend": "sqlite", "databasePath": {{System.Text.Json.JsonSerializer.Serialize(dbPath)}}, "tools": { "Bash": { "role": "Ops" } } }""");
        var db = UseAuditDatabase();

        var (exit, stdout, stderr) = await RunAsync("pre-tool-use", PreToolUse);

        Assert.Equal(2, exit);
        Assert.Empty(stdout);
        Assert.StartsWith("Sentinel internal error: ", stderr, StringComparison.Ordinal);
        Assert.DoesNotContain("approval config", stderr, StringComparison.Ordinal);
        var entry = await AssertInternalErrorEntryAsync(db, "Bash");
        Assert.Equal("cc-478", entry.SessionId);
    }

    [Theory]
    [InlineData("not json", "Sentinel internal error: malformed stdin JSON: ")]
    [InlineData("", "Sentinel internal error: malformed stdin JSON: ")]
    [InlineData("null", "Sentinel internal error: empty stdin JSON: ")]
    public async Task PreToolUse_MalformedStdin_BlocksAndRecordsIt(string json, string expectedReason)
    {
        var db = UseAuditDatabase();

        var (exit, stdout, stderr) = await RunAsync("pre-tool-use", json);

        Assert.Equal(2, exit);
        Assert.Empty(stdout);
        Assert.StartsWith(expectedReason, stderr, StringComparison.Ordinal);
        var entry = await AssertInternalErrorEntryAsync(db, "unknown");
        Assert.False(string.IsNullOrWhiteSpace(entry.SessionId));
    }

    [Fact]
    public async Task PostToolUse_MalformedStdin_ExitsOne()
    {
        var (exit, _, stderr) = await RunAsync("post-tool-use", "not json");

        Assert.Equal(1, exit);
        Assert.StartsWith("Error: malformed stdin JSON: ", stderr, StringComparison.Ordinal);
    }

    [Fact]
    public async Task PreToolUse_InternalError_WithVerbose_EmitsTheDiagnosticLine()
    {
        UseApprovalConfig("{ not json");
        Environment.SetEnvironmentVariable("SENTINEL_HOOK_VERBOSE", "1");
        try
        {
            var (exit, _, stderr) = await RunAsync("pre-tool-use", PreToolUse);

            Assert.Equal(2, exit);
            Assert.Contains("[sentinel-hook] event=pre-tool-use decision=Block session=cc-478", stderr, StringComparison.Ordinal);
            Assert.Contains("Sentinel internal error: approval config", stderr, StringComparison.Ordinal);
        }
        finally
        {
            Environment.SetEnvironmentVariable("SENTINEL_HOOK_VERBOSE", null);
        }
    }

    // With approval rules configured, a call that names no tool cannot be authorized, so it is blocked.
    [Fact]
    public async Task PreToolUse_NoToolName_WithApprovalConfig_BlocksAndRecordsIt()
    {
        UseApprovalConfig("""{ "backend": "in-memory", "tools": { "Bash": { "role": "Ops" } } }""");
        var db = UseAuditDatabase();
        Environment.SetEnvironmentVariable("SENTINEL_HOOK_VERBOSE", "1");

        var (exit, stdout, stderr) = await RunAsync("pre-tool-use", NoToolName);

        Assert.Equal(2, exit);
        Assert.Empty(stdout);
        Assert.Contains("\nSentinel internal error: PreToolUse input has no tool name\n", "\n" + stderr, StringComparison.Ordinal);
        // The verbose line names no detector for an internal error.
        var verbose = Assert.Single(stderr.Split('\n'), l => l.StartsWith("[sentinel-hook]", StringComparison.Ordinal));
        Assert.Contains("decision=Block", verbose, StringComparison.Ordinal);
        Assert.DoesNotContain("detector=", verbose, StringComparison.Ordinal);
        Assert.Contains("session=cc-478", verbose, StringComparison.Ordinal);
        var entry = await AssertInternalErrorEntryAsync(db, "unknown");
        Assert.Equal("cc-478", entry.SessionId);
    }

    // Without authorization configured there is nothing to authorize, so a missing tool name is no error.
    [Fact]
    public async Task PreToolUse_NoToolName_WithoutApprovalConfig_Allows()
    {
        Environment.SetEnvironmentVariable("SENTINEL_APPROVAL_CONFIG", null);

        var (exit, _, stderr) = await RunAsync("pre-tool-use", NoToolName);

        Assert.Equal(0, exit);
        Assert.DoesNotContain("Sentinel internal error", stderr, StringComparison.Ordinal);
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
        var db = UseAuditDatabase();
        UseApprovalConfig("{ not json");

        var (exit, _, _) = await RunAsync("pre-tool-use", PreToolUse);

        Assert.Equal(2, exit);
        var entry = await AssertInternalErrorEntryAsync(db, "Bash");
        Assert.Equal("cc-478", entry.SessionId);
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
