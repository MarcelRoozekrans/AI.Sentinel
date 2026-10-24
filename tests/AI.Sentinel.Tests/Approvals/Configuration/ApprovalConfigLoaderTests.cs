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
        Assert.Equal("DBA", config.Tools["delete_database"][0].Role);
        Assert.Equal(60, config.Tools["delete_database"][0].GrantMinutes);
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

    private ApprovalConfig LoadTools(string toolsJson, string backend = "in-memory")
    {
        File.WriteAllText(_tempPath, "{ \"backend\": \"" + backend + "\", \"tenantId\": \"t\", \"tools\": " + toolsJson + " }");
        return ApprovalConfigLoader.Load(_tempPath);
    }

    [Fact]
    public void Load_ObjectForm_IsListOfOne()
    {
        var config = LoadTools("""{ "Bash": { "role": "Ops" } }""");

        var entry = Assert.Single(config.Tools["Bash"]);
        Assert.Empty(entry.When);
        Assert.Equal(AI.Sentinel.Approvals.ApprovalGrantScope.Rule, entry.GrantScope);
    }

    [Fact]
    public void Load_ArrayForm_KeepsOrderAndWhenInFileOrder()
    {
        var config = LoadTools("""
        { "Bash": [
            { "role": "ProdOps", "grantScope": "call", "when": { "$.command": "prod", "$.cwd": "^/srv" } },
            { "role": "Operator" }
        ] }
        """);

        var list = config.Tools["Bash"];
        Assert.Equal(2, list.Count);
        Assert.Equal("ProdOps", list[0].Role);
        Assert.Equal(AI.Sentinel.Approvals.ApprovalGrantScope.Call, list[0].GrantScope);
        Assert.Equal("$.command", list[0].When[0].Key);
        Assert.Equal("$.cwd", list[0].When[1].Key);
        Assert.Equal("^/srv", list[0].When[1].Value);
        Assert.Equal("Operator", list[1].Role);
    }

    [Fact]
    public void Load_EnvPlaceholderExpandsInsideWhen()
    {
        Environment.SetEnvironmentVariable("SENTINEL_TEST_WHEN_ENV", "prod");
        try
        {
            var config = LoadTools("""{ "Bash": { "role": "R", "when": { "$.env": "^${SENTINEL_TEST_WHEN_ENV}$" } } }""");
            Assert.Equal("^prod$", config.Tools["Bash"][0].When[0].Value);
        }
        finally { Environment.SetEnvironmentVariable("SENTINEL_TEST_WHEN_ENV", null); }
    }

    [Theory]
    [InlineData("""{ "Bash": [] }""", "tools.Bash")]
    [InlineData("""{ "Bash": [ 5 ] }""", "tools.Bash[0]")]
    [InlineData("""{ "Bash": { "role": "R", "when": [] } }""", "tools.Bash.when")]
    [InlineData("""{ "Bash": { "role": "R", "when": {} } }""", "tools.Bash.when")]
    [InlineData("""{ "Bash": [ { "role": "R" }, { "role": "R", "when": { "$.a": "x" } } ] }""", "tools.Bash[1]")]
    [InlineData("""{ "Bash": [ { "role": "R", "when": { "$.a": 1 } } ] }""", "tools.Bash[0].when['$.a']")]
    [InlineData("""{ "Bash": [ { "role": "R", "when": { "$.a": "(" } } ] }""", "tools.Bash[0].when['$.a']")]
    [InlineData("""{ "Bash": { "role": "R", "grantScope": "forever" } }""", "tools.Bash.grantScope")]
    [InlineData("""{ "Bash": { "role": "R", "grantScope": 3 } }""", "tools.Bash.grantScope")]
    public void Load_InvalidRuleShapes_ThrowNamingTheLocation(string toolsJson, string expectedInMessage)
    {
        var ex = Assert.Throws<InvalidOperationException>(() => LoadTools(toolsJson));
        Assert.Contains(expectedInMessage, ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Load_EntryWithoutWhenNotLast_Throws()
    {
        var ex = Assert.Throws<InvalidOperationException>(() => LoadTools(
            """{ "Bash": [ { "role": "A" }, { "role": "B", "when": { "$.a": "x" } } ] }"""));
        Assert.Contains("tools.Bash[1]", ex.Message, StringComparison.Ordinal);
        Assert.Contains("tools.Bash[0]", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Load_BadWhenPath_WrapsArgumentExceptionNamingPath()
    {
        var ex = Assert.Throws<InvalidOperationException>(() => LoadTools(
            """{ "Bash": { "role": "R", "when": { "a.b": "x" } } }"""));
        Assert.Contains("tools.Bash.when['a.b']", ex.Message, StringComparison.Ordinal);
        Assert.IsType<ArgumentException>(ex.InnerException);
        Assert.Contains("a.b", ex.InnerException!.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Load_BadWhenValueNamesBadPatternOrPath()
    {
        var ex = Assert.Throws<InvalidOperationException>(() => LoadTools(
            """{ "Bash": [ { "role": "R", "when": { "$.a": "(" } } ] }"""));
        Assert.IsType<ArgumentException>(ex.InnerException);
        Assert.Contains("(", ex.InnerException!.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Load_GrantScopeCallWithEntraPim_Throws()
    {
        var ex = Assert.Throws<InvalidOperationException>(() => LoadTools(
            """{ "Bash": [ { "role": "R", "grantScope": "call", "when": { "$.a": "x" } } ] }""", "entra-pim"));
        Assert.Contains("tools.Bash[0]", ex.Message, StringComparison.Ordinal);
        Assert.Contains("entra-pim", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Load_GrantScopeRuleWithEntraPim_Loads() =>
        Assert.Single(LoadTools("""{ "Bash": { "role": "R", "grantScope": "rule" } }""", "entra-pim").Tools);
}
