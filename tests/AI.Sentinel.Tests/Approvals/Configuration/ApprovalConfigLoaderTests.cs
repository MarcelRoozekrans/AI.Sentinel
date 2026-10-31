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

    [Theory]
    [InlineData("""{ "Bash": { "role": "R", "grantscope": "call" } }""", "tools.Bash.grantscope", "grantScope")]
    [InlineData("""{ "Bash": [ { "role": "R", "grant_scope": "call" } ] }""", "tools.Bash[0].grant_scope", "grantScope")]
    [InlineData("""{ "Bash": [ { "role": "R", "When": { "$.a": "x" } } ] }""", "tools.Bash[0].When", "when")]
    [InlineData("""{ "Bash": { "Role": "R", "role": "R" } }""", "tools.Bash.Role", "role")]
    [InlineData("""{ "Bash": { "role": "R", "grant-minutes": 5 } }""", "tools.Bash.grant-minutes", "grantMinutes")]
    [InlineData("""{ "Bash": { "role": "R", "require_justification": true } }""", "tools.Bash.require_justification", "requireJustification")]
    public void Load_MisspelledKnownKey_ThrowsNamingLocationAndSpelling(string toolsJson, string location, string expected)
    {
        var ex = Assert.Throws<InvalidOperationException>(() => LoadTools(toolsJson));
        Assert.Contains(location, ex.Message, StringComparison.Ordinal);
        Assert.Contains($"'{expected}'", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Load_UnrelatedUnknownKey_IsAccepted() =>
        Assert.Single(LoadTools("""{ "Bash": { "role": "R", "description": "kubectl guard" } }""").Tools);

    [Fact]
    public void Load_DuplicateKeyInWhen_ThrowsNamingLocation()
    {
        var ex = Assert.Throws<InvalidOperationException>(() => LoadTools(
            """{ "Bash": [ { "role": "R", "when": { "$.a": "x", "$.a": "y" } } ] }"""));
        Assert.Contains("tools.Bash[0].when", ex.Message, StringComparison.Ordinal);
        Assert.Contains("$.a", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Load_DuplicateToolKey_ThrowsNamingLocation()
    {
        var ex = Assert.Throws<InvalidOperationException>(() => LoadTools(
            """{ "Bash": { "role": "A" }, "Bash": { "role": "B" } }"""));
        Assert.Contains("tools", ex.Message, StringComparison.Ordinal);
        Assert.Contains("Bash", ex.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("""{ "Bash": { "role": "A", "role": "B" } }""", "tools.Bash", "role")]
    [InlineData("""{ "Bash": [ { "role": "R", "when": { "$.a": "x" }, "when": { "$.b": "y" } } ] }""", "tools.Bash[0]", "when")]
    [InlineData("""{ "Bash": { "role": "R", "grantScope": "call", "grantScope": "rule" } }""", "tools.Bash", "grantScope")]
    [InlineData("""{ "Bash": { "role": "R", "description": "a", "description": "b" } }""", "tools.Bash", "description")]
    public void Load_DuplicateKeyInToolEntry_ThrowsNamingLocation(string toolsJson, string location, string key)
    {
        var ex = Assert.Throws<InvalidOperationException>(() => LoadTools(toolsJson));
        Assert.Contains($"{location} has duplicate key '{key}'", ex.Message, StringComparison.Ordinal);
    }

    private static ApprovalConfig ParseNotify(string extraKeys)
    {
        using var doc = JsonDocument.Parse("{ \"backend\": \"in-memory\", " + extraKeys + " }");
        return ApprovalConfigLoader.Parse(doc.RootElement.Clone());
    }

    [Fact]
    public void Parse_NotifyKeys_Populated()
    {
        var config = ParseNotify("""
            "notifyUrl": "https://hooks.example.com/a", "notifyHeaders": { "Authorization": "Bearer x" },
            "notifyIncludeArgs": true, "dashboardUrl": "http://localhost:5000/"
            """);
        Assert.Equal(new Uri("https://hooks.example.com/a"), config.NotifyUrl);
        Assert.Equal("Bearer x", config.NotifyHeaders["Authorization"]);
        Assert.True(config.NotifyIncludeArgs);
        Assert.Equal(new Uri("http://localhost:5000/"), config.DashboardUrl);
    }

    [Fact]
    public void Parse_NoNotifyKeys_Defaults()
    {
        var config = ParseNotify("\"tenantId\": \"t\"");
        Assert.Null(config.NotifyUrl);
        Assert.Empty(config.NotifyHeaders);
        Assert.False(config.NotifyIncludeArgs);
        Assert.Null(config.DashboardUrl);
    }

    [Theory]
    [InlineData("")]
    [InlineData("relative/path")]
    [InlineData("/relative/path")]
    [InlineData("ftp://x")]
    [InlineData("not a url")]
    public void Parse_NotifyUrl_Invalid_Throws(string value)
    {
        var ex = Assert.Throws<InvalidOperationException>(() => ParseNotify($"\"notifyUrl\": \"{value}\""));
        Assert.Contains("notifyUrl", ex.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("notifyUrl", "hooks.example.com/services/T/B/s3cret", "is not an absolute URL")]
    [InlineData("notifyUrl", "htps://hooks.example.com/services/T/B/s3cret", "has scheme 'htps'")]
    [InlineData("notifyUrl", "ftp://hooks.example.com/services/T/B/s3cret", "has scheme 'ftp'")]
    [InlineData("notifyUrl", "s3cret:token", "must use http or https")]
    [InlineData("notifyUrl", "", "is empty")]
    [InlineData("dashboardUrl", "dash.example.com/s3cret", "is not an absolute URL")]
    public void Parse_InvalidUrl_NeverQuotesTheValue(string key, string value, string expected)
    {
        var json = string.Equals(key, "notifyUrl", StringComparison.Ordinal) ? $"\"notifyUrl\": \"{value}\"" : $"\"notifyUrl\": \"https://h.example.com/\", \"dashboardUrl\": \"{value}\"";
        var ex = Assert.Throws<InvalidOperationException>(() => ParseNotify(json));
        Assert.Contains(key, ex.Message, StringComparison.Ordinal);
        Assert.Contains(expected, ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("s3cret", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Parse_NonStringUrl_DoesNotEchoTheValue()
    {
        var ex = Assert.Throws<InvalidOperationException>(() => ParseNotify("\"notifyUrl\": { \"k\": \"s3cret\" }"));
        Assert.Contains("notifyUrl", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("s3cret", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Parse_NotifyHeaderErrors_NameTheHeaderNotTheValue()
    {
        var ex = Assert.Throws<InvalidOperationException>(() => ParseNotify(
            "\"notifyUrl\": \"https://h.example.com/\", \"notifyHeaders\": { \"Bad Name\": \"s3cret\" }"));
        Assert.Contains("Bad Name", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("s3cret", ex.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("relative")]
    [InlineData("/relative/path")]
    public void Parse_DashboardUrl_Invalid_Throws(string value)
    {
        var ex = Assert.Throws<InvalidOperationException>(() => ParseNotify($"\"dashboardUrl\": \"{value}\""));
        Assert.Contains("dashboardUrl", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Parse_NotifyHeadersWithoutUrl_Throws()
    {
        var ex = Assert.Throws<InvalidOperationException>(() => ParseNotify("\"notifyHeaders\": { \"X-A\": \"b\" }"));
        Assert.Contains("notifyHeaders", ex.Message, StringComparison.Ordinal);
        Assert.Contains("notifyUrl", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Parse_NotifyIncludeArgsWithoutUrl_Throws()
    {
        var ex = Assert.Throws<InvalidOperationException>(() => ParseNotify("\"notifyIncludeArgs\": true"));
        Assert.Contains("notifyIncludeArgs", ex.Message, StringComparison.Ordinal);
        Assert.Contains("notifyUrl", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Parse_DashboardUrlAlone_Loads()
    {
        var config = ParseNotify("\"dashboardUrl\": \"https://d.example.com/\"");
        Assert.NotNull(config.DashboardUrl);
        Assert.Null(config.NotifyUrl);
    }

    [Fact]
    public void Parse_NotifyHeaders_NonString_Throws()
    {
        var ex = Assert.Throws<InvalidOperationException>(() => ParseNotify(
            "\"notifyUrl\": \"https://h.example.com/\", \"notifyHeaders\": { \"X-A\": 1 }"));
        Assert.Contains("notifyHeaders['X-A']", ex.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("Content-Type")]
    [InlineData("content-length")]
    [InlineData("Bad Name")]
    public void Parse_NotifyHeaders_ForbiddenOrInvalidName_Throws(string name)
    {
        var ex = Assert.Throws<InvalidOperationException>(() => ParseNotify(
            $"\"notifyUrl\": \"https://h.example.com/\", \"notifyHeaders\": {{ \"{name}\": \"v\" }}"));
        Assert.Contains("notifyHeaders", ex.Message, StringComparison.Ordinal);
        Assert.Contains(name, ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Load_ExpandsEnvInNotifyUrlAndHeaders()
    {
        Environment.SetEnvironmentVariable("SENTINEL_TEST_458_HOST", "hooks.example.com");
        Environment.SetEnvironmentVariable("SENTINEL_TEST_458_TOKEN", "s3cret");
        try
        {
            File.WriteAllText(_tempPath, """
            { "backend": "in-memory", "notifyUrl": "https://${SENTINEL_TEST_458_HOST}/x",
              "notifyHeaders": { "Authorization": "Bearer ${SENTINEL_TEST_458_TOKEN}" } }
            """);
            var config = ApprovalConfigLoader.Load(_tempPath);
            Assert.Equal("hooks.example.com", config.NotifyUrl!.Host);
            Assert.Equal("Bearer s3cret", config.NotifyHeaders["Authorization"]);
        }
        finally
        {
            Environment.SetEnvironmentVariable("SENTINEL_TEST_458_HOST", null);
            Environment.SetEnvironmentVariable("SENTINEL_TEST_458_TOKEN", null);
        }
    }

    [Fact]
    public void Load_UnsetEnvInNotifyUrl_Throws()
    {
        // The expander turns an unset variable into an empty string, which the URL check then rejects.
        File.WriteAllText(_tempPath, "{ \"backend\": \"in-memory\", \"notifyUrl\": \"${UNSET_458_VAR}\" }");
        var ex = Assert.Throws<InvalidOperationException>(() => ApprovalConfigLoader.Load(_tempPath));
        Assert.Contains("notifyUrl is empty", ex.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("\"notifyUrl\": 5", "notifyUrl")]
    [InlineData("\"dashboardUrl\": 5", "dashboardUrl")]
    [InlineData("\"notifyUrl\": \"https://h.example.com/\", \"notifyIncludeArgs\": \"yes\"", "notifyIncludeArgs")]
    [InlineData("\"notifyUrl\": \"https://h.example.com/\", \"notifyHeaders\": { \"X-A\": \"1\", \"X-A\": \"2\" }", "notifyHeaders")]
    [InlineData("\"notifyUrl\": \"https://h.example.com/\", \"notifyHeaders\": { \"X-A\": \"1\", \"x-a\": \"2\" }", "duplicate key")]
    public void Parse_WrongTypeOrDuplicate_ThrowsNamingKey(string json, string expected)
    {
        var ex = Assert.Throws<InvalidOperationException>(() => ParseNotify(json));
        Assert.Contains(expected, ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Load_UnsetEnvInNotifyHeaderValue_Throws()
    {
        File.WriteAllText(_tempPath, """
        { "backend": "in-memory", "notifyUrl": "https://h.example.com/",
          "notifyHeaders": { "Authorization": "${UNSET_458_HDR}" } }
        """);
        var ex = Assert.Throws<InvalidOperationException>(() => ApprovalConfigLoader.Load(_tempPath));
        Assert.Contains("notifyHeaders['Authorization']", ex.Message, StringComparison.Ordinal);
    }
}
