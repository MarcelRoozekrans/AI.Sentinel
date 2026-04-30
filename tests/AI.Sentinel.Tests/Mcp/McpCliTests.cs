using Xunit;
using AI.Sentinel.Approvals.EntraPim;
using AI.Sentinel.Approvals.Sqlite;
using AI.Sentinel.Mcp.Cli;

namespace AI.Sentinel.Tests.Mcp;

[Collection("NonParallel")]
public class McpCliTests
{
    [Fact]
    public async Task NoArgs_ExitsOneWithUsage()
    {
        var stdin = new StringReader("");
        var stdout = new StringWriter();
        var stderr = new StringWriter();

        var exit = await Program.RunAsync(Array.Empty<string>(), stdin, stdout, stderr);

        Assert.Equal(1, exit);
        Assert.Contains("Usage", stderr.ToString(), StringComparison.Ordinal);
        Assert.Contains("--target", stderr.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task UnknownSubcommand_ExitsOneWithUsage()
    {
        var stdin = new StringReader("");
        var stdout = new StringWriter();
        var stderr = new StringWriter();

        var exit = await Program.RunAsync(new[] { "foo" }, stdin, stdout, stderr);

        Assert.Equal(1, exit);
        Assert.Contains("Usage", stderr.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task ProxyWithoutTarget_ExitsOneWithUsage()
    {
        var stdin = new StringReader("");
        var stdout = new StringWriter();
        var stderr = new StringWriter();

        var exit = await Program.RunAsync(new[] { "proxy" }, stdin, stdout, stderr);

        Assert.Equal(1, exit);
        Assert.Contains("--target", stderr.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task ProxyWithMissingTargetBinary_ExitsTwo()
    {
        var stdin = new StringReader("");
        var stdout = new StringWriter();
        var stderr = new StringWriter();

        // A binary name that definitely doesn't exist on PATH.
        var exit = await Program.RunAsync(
            new[] { "proxy", "--target", "this-binary-does-not-exist-xyz-abc-42" },
            stdin, stdout, stderr);

        Assert.Equal(2, exit);
        Assert.Contains("target process failed", stderr.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task BuildAuthorizationStack_SqliteBackend_RegistersSqliteApprovalStore()
    {
        // Stage 5 Task 5.6 bundled the Sqlite backend into the MCP CLI. The auth-stack builder
        // reads SENTINEL_APPROVAL_CONFIG, dispatches to AddSentinelSqliteApprovalStore, and
        // returns the resolved IApprovalStore. Direct inspection that the right store was
        // registered (vs. the previous "throw at startup" branch).
        var configPath = Path.Combine(Path.GetTempPath(), $"approval-{Guid.NewGuid():N}.json");
        var dbPath = Path.Combine(Path.GetTempPath(), $"approvals-mcp-{Guid.NewGuid():N}.db");
        await File.WriteAllTextAsync(configPath, $$"""
            {
                "backend": "sqlite",
                "databasePath": {{System.Text.Json.JsonSerializer.Serialize(dbPath)}},
                "tools": { "Bash": { "role": "DBA" } }
            }
            """);
        Environment.SetEnvironmentVariable("SENTINEL_APPROVAL_CONFIG", configPath);
        try
        {
            var stderr = new StringWriter();
            var (provider, _, store, _, configError) = await ProxyCommand.BuildAuthorizationStackAsync(stderr);
            try
            {
                Assert.False(configError);
                Assert.IsType<SqliteApprovalStore>(store);
                Assert.True(File.Exists(dbPath), "SqliteApprovalStore should have created the database file.");
            }
            finally
            {
                if (provider is not null) await provider.DisposeAsync();
            }
        }
        finally
        {
            Environment.SetEnvironmentVariable("SENTINEL_APPROVAL_CONFIG", null);
            File.Delete(configPath);
            foreach (var path in new[] { dbPath, dbPath + "-wal", dbPath + "-shm" })
                if (File.Exists(path)) File.Delete(path);
        }
    }

    [Fact]
    public async Task BuildAuthorizationStack_EntraPimBackend_RegistersEntraPimApprovalStore()
    {
        var configPath = Path.Combine(Path.GetTempPath(), $"approval-{Guid.NewGuid():N}.json");
        await File.WriteAllTextAsync(configPath, """
            {
                "backend": "entra-pim",
                "tenantId": "11111111-1111-1111-1111-111111111111",
                "tools": { "Bash": { "role": "Privileged Role Administrator" } }
            }
            """);
        Environment.SetEnvironmentVariable("SENTINEL_APPROVAL_CONFIG", configPath);
        try
        {
            var stderr = new StringWriter();
            var (provider, _, store, _, configError) = await ProxyCommand.BuildAuthorizationStackAsync(stderr);
            try
            {
                Assert.False(configError);
                Assert.IsType<EntraPimApprovalStore>(store);
            }
            finally
            {
                if (provider is not null) await provider.DisposeAsync();
            }
        }
        finally
        {
            Environment.SetEnvironmentVariable("SENTINEL_APPROVAL_CONFIG", null);
            File.Delete(configPath);
        }
    }
}
