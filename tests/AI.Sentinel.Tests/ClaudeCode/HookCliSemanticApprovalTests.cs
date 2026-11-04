using Xunit;
using AI.Sentinel.ClaudeCode.Cli;
using AI.Sentinel.Tests.Helpers;
using Microsoft.Extensions.AI;

namespace AI.Sentinel.Tests.ClaudeCode;

/// <summary>Semantic approvals end to end in the Claude Code hook: a config with only a <c>semantic</c> block gates
/// a destructive <c>Bash</c> command behind an approval (#477).</summary>
[Collection("NonParallel")]
public class HookCliSemanticApprovalTests : IDisposable
{
    // A verbatim built-in example, so ExactMatchEmbeddingGenerator scores it 1.0.
    private const string Destructive = "kubectl delete namespace production";

    private const string InertWarning = "the semantic layer is inert";

    private const string SemanticOnlyConfig = """
        { "backend": "in-memory", "semantic": { "tools": { "Bash": { "role": "Ops" } } } }
        """;

    private readonly string _dir = HookAuditTestSupport.NewTempDir();
    private readonly string? _prevConfig = Environment.GetEnvironmentVariable("SENTINEL_APPROVAL_CONFIG");
    private readonly string? _prevSqlite = Environment.GetEnvironmentVariable(HookAuditTestSupport.SqliteVar);

    public HookCliSemanticApprovalTests()
    {
        Environment.SetEnvironmentVariable(HookAuditTestSupport.SqliteVar, "off");
        var path = Path.Combine(_dir, "approvals.json");
        File.WriteAllText(path, SemanticOnlyConfig);
        Environment.SetEnvironmentVariable("SENTINEL_APPROVAL_CONFIG", path);
    }

    public void Dispose()
    {
        Environment.SetEnvironmentVariable("SENTINEL_APPROVAL_CONFIG", _prevConfig);
        Environment.SetEnvironmentVariable(HookAuditTestSupport.SqliteVar, _prevSqlite);
        HookAuditTestSupport.DeleteDir(_dir);
        GC.SuppressFinalize(this);
    }

    private static async Task<(int Exit, string Stderr)> PreToolUseAsync(
        string command, IEmbeddingGenerator<string, Embedding<float>>? generator)
    {
        var stdin = new StringReader($$$"""{"session_id":"s","tool_name":"Bash","tool_input":{"command":"{{{command}}}"}}""");
        var stderr = new StringWriter();
        var exit = await Program.RunAsync(["pre-tool-use"], stdin, new StringWriter(), stderr, generator);
        return (exit, stderr.ToString());
    }

    [Fact]
    public async Task Semantic_DestructiveBashCommand_BlocksWithTheSemanticReceipt()
    {
        var (exit, stderr) = await PreToolUseAsync(Destructive, new ExactMatchEmbeddingGenerator());

        Assert.Equal(2, exit);
        Assert.Contains("Rule: semantic:Bash#", stderr, StringComparison.Ordinal);
        Assert.Contains("Reason: Semantic match", stderr, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Semantic_EmbeddingFailure_BlocksFailClosed()
    {
        var (exit, stderr) = await PreToolUseAsync(Destructive, new ThrowingEmbeddingGenerator());

        Assert.Equal(2, exit);
        Assert.Contains("Rule: semantic:Bash#", stderr, StringComparison.Ordinal);
        Assert.Contains("Reason: Semantic check failed:", stderr, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Semantic_BenignBashCommand_IsAllowed()
    {
        var (exit, stderr) = await PreToolUseAsync("ls -la", new ExactMatchEmbeddingGenerator());

        Assert.Equal(0, exit);
        Assert.DoesNotContain("semantic:", stderr, StringComparison.Ordinal);
        Assert.DoesNotContain(InertWarning, stderr, StringComparison.Ordinal);
    }

    // No logging provider in the hook, so the guard's warning that the layer is inert goes to stderr, once.
    [Fact]
    public async Task Semantic_NoEmbeddingGenerator_WarnsOnceThatTheLayerIsInert()
    {
        var (exit, stderr) = await PreToolUseAsync("ls -la", generator: null);

        Assert.Equal(0, exit);
        var line = Assert.Single(stderr.Split('\n'), l => l.Contains(InertWarning, StringComparison.Ordinal));
        Assert.StartsWith("[sentinel-hook] ", line, StringComparison.Ordinal);
    }
}
