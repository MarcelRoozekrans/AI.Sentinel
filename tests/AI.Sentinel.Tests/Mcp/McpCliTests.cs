using Xunit;
using AI.Sentinel.Tests.Helpers;
using AI.Sentinel.Approvals;
using AI.Sentinel.Approvals.EntraPim;
using AI.Sentinel.Approvals.Sqlite;
using AI.Sentinel.Mcp.Cli;
using Microsoft.Extensions.DependencyInjection;

namespace AI.Sentinel.Tests.Mcp;

[Collection("NonParallel")]
public class McpCliTests : McpAuditOffFixtureBase
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
            """, TestContext.Current.CancellationToken);
        Environment.SetEnvironmentVariable("SENTINEL_APPROVAL_CONFIG", configPath);
        try
        {
            var stderr = new StringWriter();
            var (provider, _, store, _, configError) = await ProxyCommand.BuildAuthorizationStackAsync(stderr);
            try
            {
                Assert.False(configError);
                // The proxy gets the store DI hands out, the auditing wrapper, so approval decisions reach the audit log.
                Assert.IsType<AuditingApprovalAdminStore>(store);
                Assert.Same(provider!.GetService<IApprovalStore>(), store);
                Assert.IsType<SqliteApprovalStore>(provider!.GetRequiredKeyedService<IApprovalStore>(ApprovalStoreAuditing.InnerStoreKey));
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
            """, TestContext.Current.CancellationToken);
        Environment.SetEnvironmentVariable("SENTINEL_APPROVAL_CONFIG", configPath);
        try
        {
            var stderr = new StringWriter();
            var (provider, _, store, _, configError) = await ProxyCommand.BuildAuthorizationStackAsync(stderr);
            try
            {
                Assert.False(configError);
                Assert.IsType<AuditingApprovalStore>(store);
                Assert.Same(provider!.GetService<IApprovalStore>(), store);
                Assert.IsType<EntraPimApprovalStore>(provider!.GetRequiredKeyedService<IApprovalStore>(ApprovalStoreAuditing.InnerStoreKey));
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

    [Fact]
    public async Task BuildAuthorizationStack_WithAuditStore_WritesApprovalDecisionsToIt()
    {
        var configPath = Path.Combine(Path.GetTempPath(), $"approval-{Guid.NewGuid():N}.json");
        await File.WriteAllTextAsync(configPath, """
            {
                "backend": "in-memory",
                "tools": { "Bash": { "role": "DBA" } }
            }
            """, TestContext.Current.CancellationToken);
        Environment.SetEnvironmentVariable("SENTINEL_APPROVAL_CONFIG", configPath);
        try
        {
            using var auditStore = new AI.Sentinel.Audit.RingBufferAuditStore();
            var (provider, _, store, _, configError) =
                await ProxyCommand.BuildAuthorizationStackAsync(new StringWriter(), auditStore, []);
            try
            {
                Assert.False(configError);
                Assert.Same(auditStore, provider!.GetService<AI.Sentinel.Audit.IAuditStore>());

                var pending = await store!.EnsureRequestAsync(
                    new Caller(), new ApprovalSpec { PolicyName = "DBA" },
                    new ApprovalContext("Bash", default, null), TestContext.Current.CancellationToken);
                var requestId = Assert.IsType<ApprovalState.Pending>(pending).RequestId;
                await store.WaitForDecisionAsync(requestId, TimeSpan.FromMilliseconds(10), TestContext.Current.CancellationToken);

                var entries = new List<AI.Sentinel.Audit.AuditEntry>();
                await foreach (var e in auditStore.QueryAsync(new AI.Sentinel.Audit.AuditQuery(), TestContext.Current.CancellationToken))
                    entries.Add(e);
                var entry = Assert.Single(entries);
                Assert.Equal(AI.Sentinel.Audit.AuditEntryKinds.TimedOutPolicyCode, entry.PolicyCode);
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

    private sealed class Caller : ZeroAlloc.Authorization.ISecurityContext
    {
        public string Id => "caller";
        public IReadOnlySet<string> Roles { get; } = new HashSet<string>(StringComparer.Ordinal);
        public IReadOnlyDictionary<string, string> Claims { get; } = new Dictionary<string, string>(StringComparer.Ordinal);
    }

    // SENTINEL_MCP_COMPLIANCE turns the opt-in compliance detectors on or off for the proxy; unset, it falls
    // back to SENTINEL_HOOK_COMPLIANCE, as the severity settings fall back to SENTINEL_HOOK_ON_*.
    [Theory]
    [InlineData(null, null, false)]
    [InlineData("on", null, true)]
    [InlineData("off", null, false)]
    [InlineData(null, "on", true)]
    [InlineData("off", "on", false)]
    [InlineData("banana", "on", true)]
    public void ComplianceSwitch_EnablesTheComplianceDetectors(string? mcp, string? hook, bool expected)
    {
        var env = new Dictionary<string, string?>(StringComparer.Ordinal)
        {
            ["SENTINEL_MCP_COMPLIANCE"] = mcp,
            ["SENTINEL_HOOK_COMPLIANCE"] = hook,
        };

        var config = ProxyCommand.ResolveHookConfig(["proxy", "--target", "x"], env);

        Assert.Equal(expected, config.EnableComplianceDetectors);
    }

    // SENTINEL_MCP_REDACT turns proxy redaction on or off; unset, it falls back to SENTINEL_HOOK_REDACT, and both
    // unset leave it on.
    [Theory]
    [InlineData("off", "on", false)]
    [InlineData("on", "off", true)]
    [InlineData(null, "off", false)]
    [InlineData(null, null, true)]
    public void ResolveHookConfig_McpRedactOverridesHookRedact(string? mcp, string? hook, bool expected)
    {
        var env = new Dictionary<string, string?>(StringComparer.Ordinal)
        {
            ["SENTINEL_MCP_REDACT"] = mcp,
            ["SENTINEL_HOOK_REDACT"] = hook,
        };

        var config = ProxyCommand.ResolveHookConfig(["proxy", "--target", "x"], env);

        Assert.Equal(expected, config.RedactToolResults);
    }

    // SENTINEL_MCP_REDACT_TTL_MIN is a positive number of minutes; anything else keeps the 30-minute default.
    [Theory]
    [InlineData("5", 5)]
    [InlineData("0", 30)]
    [InlineData("x", 30)]
    [InlineData(null, 30)]
    public void ParseRedactionIdleExpiry(string? value, int expectedMinutes)
    {
        var env = new Dictionary<string, string?>(StringComparer.Ordinal) { ["SENTINEL_MCP_REDACT_TTL_MIN"] = value };

        Assert.Equal(TimeSpan.FromMinutes(expectedMinutes), ProxyCommand.ParseRedactionIdleExpiry(env));
    }

    // SENTINEL_MCP_MAX_SCAN_BYTES is a positive byte count; anything else keeps the single 262144 default.
    [Theory]
    [InlineData("100", 100)]
    [InlineData("0", 262144)]
    [InlineData("-5", 262144)]
    [InlineData("x", 262144)]
    [InlineData(null, 262144)]
    public void ParseMaxScanBytes(string? value, int expected)
    {
        var env = new Dictionary<string, string?>(StringComparer.Ordinal) { ["SENTINEL_MCP_MAX_SCAN_BYTES"] = value };

        Assert.Equal(expected, ProxyCommand.ParseMaxScanBytes(env));
    }
}
