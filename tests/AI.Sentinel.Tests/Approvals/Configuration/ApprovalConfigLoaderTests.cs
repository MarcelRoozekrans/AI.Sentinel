using AI.Sentinel.Approvals.Configuration;
using System.Text.Json;
using Xunit;

namespace AI.Sentinel.Tests.Approvals.Configuration;

public class ApprovalConfigLoaderTests : IDisposable
{
    private readonly string _tempPath = Path.Combine(Path.GetTempPath(), $"approval-config-{Guid.NewGuid():N}.json");

    public void Dispose()
    {
        if (File.Exists(_tempPath)) File.Delete(_tempPath);
    }

    [Fact]
    public void Load_ValidFile_ReturnsConfig()
    {
        File.WriteAllText(_tempPath, """
        {
            "backend": "in-memory",
            "defaultGrantMinutes": 30,
            "tools": {
                "delete_database": { "role": "DBA", "grantMinutes": 60 }
            }
        }
        """);

        var config = ApprovalConfigLoader.Load(_tempPath);

        Assert.Equal("in-memory", config.Backend);
        Assert.Equal(30, config.DefaultGrantMinutes);
        Assert.Equal("AI agent invocation: {tool}", config.DefaultJustificationTemplate); // default
        Assert.True(config.IncludeConversationContext); // default
        Assert.Single(config.Tools);
        Assert.Equal("DBA", config.Tools["delete_database"].Role);
        Assert.Equal(60, config.Tools["delete_database"].GrantMinutes);
    }

    [Fact]
    public void Load_MissingFile_ThrowsFileNotFound()
    {
        Assert.Throws<FileNotFoundException>(() =>
            ApprovalConfigLoader.Load("/nonexistent/path/config.json"));
    }

    [Fact]
    public void Load_InvalidJson_ThrowsJsonException()
    {
        File.WriteAllText(_tempPath, "{ invalid json }");
        Assert.ThrowsAny<JsonException>(() => ApprovalConfigLoader.Load(_tempPath));
    }

    [Fact]
    public void Load_MissingBackend_ThrowsInvalidOperation()
    {
        File.WriteAllText(_tempPath, """{ "defaultGrantMinutes": 30 }""");
        var ex = Assert.Throws<InvalidOperationException>(() => ApprovalConfigLoader.Load(_tempPath));
        Assert.Contains("backend", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Load_InvalidBackend_ThrowsInvalidOperation()
    {
        File.WriteAllText(_tempPath, """{ "backend": "made-up-store" }""");
        var ex = Assert.Throws<InvalidOperationException>(() => ApprovalConfigLoader.Load(_tempPath));
        Assert.Contains("in-memory, sqlite, entra-pim, none", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Load_EnvPlaceholderExpands()
    {
        Environment.SetEnvironmentVariable("SENTINEL_TEST_TID", "00000000-0000-0000-0000-000000000001");
        try
        {
            File.WriteAllText(_tempPath, """
            {
                "backend": "entra-pim",
                "tenantId": "${SENTINEL_TEST_TID}"
            }
            """);
            var config = ApprovalConfigLoader.Load(_tempPath);
            Assert.Equal("00000000-0000-0000-0000-000000000001", config.TenantId);
        }
        finally
        {
            Environment.SetEnvironmentVariable("SENTINEL_TEST_TID", null);
        }
    }

    [Fact]
    public void Load_GlobToolPattern_PreservesAsKey()
    {
        File.WriteAllText(_tempPath, """
        {
            "backend": "in-memory",
            "tools": { "deploy_*": { "role": "DeployApprover" } }
        }
        """);
        var config = ApprovalConfigLoader.Load(_tempPath);
        Assert.True(config.Tools.ContainsKey("deploy_*"));
    }

    [Fact]
    public void Load_SqliteBackend_RequiresDatabasePath()
    {
        File.WriteAllText(_tempPath, """{ "backend": "sqlite" }""");
        var ex = Assert.Throws<InvalidOperationException>(() => ApprovalConfigLoader.Load(_tempPath));
        Assert.Contains("databasePath", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Load_SqliteBackend_WithDatabasePath_Succeeds()
    {
        File.WriteAllText(_tempPath, """
        {
            "backend": "sqlite",
            "databasePath": "/var/lib/sentinel/approvals.db"
        }
        """);
        var config = ApprovalConfigLoader.Load(_tempPath);
        Assert.Equal("sqlite", config.Backend);
        Assert.Equal("/var/lib/sentinel/approvals.db", config.DatabasePath);
    }

    [Fact]
    public void Load_EntraPimBackend_RequiresTenantId()
    {
        File.WriteAllText(_tempPath, """{ "backend": "entra-pim" }""");
        var ex = Assert.Throws<InvalidOperationException>(() => ApprovalConfigLoader.Load(_tempPath));
        Assert.Contains("tenantId", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ExpandEnvPlaceholders_UnsetVarBecomesEmptyString()
    {
        var input = "tenant=${DEFINITELY_NOT_SET_VAR_12345}";
        var output = ApprovalConfigLoader.ExpandEnvPlaceholders(input);
        Assert.Equal("tenant=", output);
    }
}
