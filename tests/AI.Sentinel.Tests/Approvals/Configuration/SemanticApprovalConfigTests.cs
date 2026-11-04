using System.Text.Json;
using AI.Sentinel.Approvals.Configuration;
using Xunit;

namespace AI.Sentinel.Tests.Approvals.Configuration;

public class SemanticApprovalConfigTests
{
    private static ApprovalConfig Parse(string json) =>
        ApprovalConfigLoader.Parse(JsonDocument.Parse(json).RootElement);

    private static string Config(string semantic, string backend = "in-memory") =>
        $$"""{ "backend": "{{backend}}", "defaultGrantMinutes": 20, "semantic": {{semantic}} }""";

    [Fact]
    public void FullBlock_RoundTrips()
    {
        var config = Parse(Config("""
        {
          "threshold": 0.8,
          "examples": ["decommission a tenant"],
          "replaceExamples": false,
          "tools": {
            "Bash": { "role": "Operator" },
            "mcp__api__http_request": { "role": "Operator", "paths": ["$.method", "$.url"], "grantMinutes": 30, "requireJustification": false, "threshold": 0.9 }
          }
        }
        """));

        var s = config.Semantic!;
        Assert.Equal(0.8f, s.Threshold);
        Assert.Equal(["decommission a tenant"], s.Examples);
        Assert.False(s.ReplaceExamples);
        Assert.Equal(["Bash", "mcp__api__http_request"], s.Tools.Select(t => t.Key), StringComparer.Ordinal);
        Assert.Equal(new SemanticToolConfig("Operator", null, null, null, null), s.Tools[0].Value);
        var http = s.Tools[1].Value;
        Assert.Equal("Operator", http.Role);
        Assert.Equal(30, http.GrantMinutes);
        Assert.False(http.RequireJustification);
        Assert.Equal(["$.method", "$.url"], http.Paths);
        Assert.Equal(0.9f, http.Threshold);
    }

    [Fact]
    public void MinimalBlock_UsesDefaults()
    {
        var s = Parse(Config("""{ "tools": { "Bash": { "role": "Op" } } }""")).Semantic!;
        Assert.Null(s.Threshold);
        Assert.Empty(s.Examples);
        Assert.False(s.ReplaceExamples);
    }

    [Fact]
    public void ReplaceExamples_WithExamples_Parses()
    {
        var s = Parse(Config("""{ "replaceExamples": true, "examples": ["x"], "tools": { "Bash": { "role": "Op" } } }""")).Semantic!;
        Assert.True(s.ReplaceExamples);
    }

    [Fact]
    public void NoSemanticBlock_IsNull() =>
        Assert.Null(Parse("""{ "backend": "in-memory", "tools": { "t": { "role": "r" } } }""").Semantic);

    public static TheoryData<string, string, string> BadBlocks => new()
    {
        { """{ "tools": { "Bash": { "role": "Op" } }, "bogus": 1 }""", "semantic", "bogus" },
        { """{ "tools": { "Bash": { "role": "Op", "grantScope": "call" } } }""", "semantic.tools.Bash", "grantScope" },
        { """{ "tools": { "Bash": { "role": "Op", "colour": 1 } } }""", "semantic.tools.Bash", "colour" },
        { """{ }""", "semantic", "tools" },
        { """{ "tools": { } }""", "semantic", "tools" },
        { """{ "tools": { "Bash": { } } }""", "semantic.tools.Bash", "role" },
        { """{ "tools": { "Bash": { "role": "Op", "paths": [] } } }""", "semantic.tools.Bash", "paths" },
        { """{ "tools": { "Bash": { "role": "Op", "paths": ["command"] } } }""", "semantic.tools.Bash", "paths[0]" },
        { """{ "examples": ["ok", "  "], "tools": { "Bash": { "role": "Op" } } }""", "semantic", "examples[1]" },
        { """{ "replaceExamples": true, "tools": { "Bash": { "role": "Op" } } }""", "semantic", "replaceExamples" },
        { """{ "replaceExamples": true, "examples": [], "tools": { "Bash": { "role": "Op" } } }""", "semantic", "replaceExamples" },
        { """{ "threshold": 0, "tools": { "Bash": { "role": "Op" } } }""", "semantic", "threshold" },
        { """{ "threshold": 1.5, "tools": { "Bash": { "role": "Op" } } }""", "semantic", "threshold" },
        { """{ "tools": { "Bash": { "role": "Op", "threshold": 0 } } }""", "semantic.tools.Bash", "threshold" },
        { """{ "tools": { "Bash": { "role": "Op", "threshold": 2 } } }""", "semantic.tools.Bash", "threshold" },
        { """{ "tools": { "Bash": { "role": "Op", "grantMinutes": 0 } } }""", "semantic.tools.Bash", "grantMinutes" },
        { """{ "tools": { "Bash": { "role": "Op" }, "Bash": { "role": "Op" } } }""", "semantic", "Bash" },
    };

    [Theory]
    [MemberData(nameof(BadBlocks))]
    public void BadBlock_FailsAtLoad(string block, string location, string field)
    {
        var ex = Assert.Throws<InvalidOperationException>(() => Parse(Config(block)));
        Assert.Contains(location, ex.Message);
        Assert.Contains(field, ex.Message);
    }

    [Theory]
    [InlineData("entra-pim")]
    [InlineData("none")]
    public void UnsupportedBackend_FailsAtLoad(string backend)
    {
        var json = $$"""{ "backend": "{{backend}}", "tenantId": "t", "semantic": { "tools": { "Bash": { "role": "Op" } } } }""";
        var ex = Assert.Throws<InvalidOperationException>(() => Parse(json));
        Assert.Contains("semantic", ex.Message);
        Assert.Contains(backend, ex.Message);
    }

    [Fact]
    public void Configure_RegistersToolsInFileOrderWithDefaults()
    {
        var config = Parse(Config("""
        {
          "threshold": 0.7,
          "examples": ["a", "b"],
          "replaceExamples": true,
          "tools": {
            "Zed": { "role": "R1" },
            "Alpha*": { "role": "R2", "grantMinutes": 5, "requireJustification": false, "paths": ["$.x"], "threshold": 0.95 }
          }
        }
        """));
        var opts = new SentinelOptions();

        ApprovalBackendSelector.Configure(opts, config);

        var (settings, tools) = opts.GetSemanticApprovals();
        Assert.Equal(0.7f, settings.Threshold);
        Assert.True(settings.ReplaceExamples);
        Assert.Equal(["a", "b"], settings.AddedExamples);
        Assert.Equal(["Zed", "Alpha*"], tools.Select(t => t.Pattern), StringComparer.Ordinal);
        var zed = tools[0].Spec;
        Assert.Equal("R1", zed.BackendBinding);
        Assert.Equal(TimeSpan.FromMinutes(20), zed.GrantDuration);
        Assert.True(zed.RequireJustification);
        Assert.Equal(TimeSpan.FromMinutes(5), zed.WaitTimeout);
        Assert.Null(zed.Threshold);
        Assert.Null(zed.ParsedPaths);
        var alpha = tools[1].Spec;
        Assert.Equal(TimeSpan.FromMinutes(5), alpha.GrantDuration);
        Assert.False(alpha.RequireJustification);
        Assert.Equal(0.95f, alpha.Threshold);
        Assert.Equal(["$.x"], alpha.ParsedPaths!.Select(p => p.Text), StringComparer.Ordinal);
    }

    [Fact]
    public void Configure_WithoutSemantic_RegistersNone()
    {
        var opts = new SentinelOptions();
        ApprovalBackendSelector.Configure(opts, Parse("""{ "backend": "in-memory", "tools": { "t": { "role": "r" } } }"""));
        Assert.Empty(opts.GetSemanticApprovals().Tools);
    }
}
