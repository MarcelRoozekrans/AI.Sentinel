using System.Text.Json;
using AI.Sentinel.Approvals.Conditions;
using Xunit;

namespace AI.Sentinel.Tests.Approvals.Conditions;

public class ArgumentPathTests
{
    private const string Doc = "{\"a\":{\"b c\":[10,\"x\"]},\"m\":\"GET\"}";

    [Theory]
    [InlineData("$.m", "GET")]
    [InlineData("$['a']['b c'][1]", "x")]
    [InlineData("$.a['b c'][0]", "10")]
    [InlineData("$.a", "{\"b c\":[10,\"x\"]}")]
    public void Resolve_ResolvesPath(string path, string expected)
    {
        using var doc = JsonDocument.Parse(Doc);
        Assert.Equal(ArgumentPathResult.Resolved, ArgumentPath.Parse(path).Resolve(doc.RootElement, out var text));
        Assert.Equal(expected, text);
    }

    [Theory]
    [InlineData("{\"v\":true}", "$.v", "true")]
    [InlineData("{\"v\":[1, [2,  3], {\"k\": \"z\"}]}", "$.v", "[1,[2,3],{\"k\":\"z\"}]")]
    [InlineData("{\"v\":\"a\\u00e9\"}", "$.v", "a\u00e9")]
    public void Resolve_ValueKinds(string json, string path, string expected)
    {
        using var doc = JsonDocument.Parse(json);
        Assert.Equal(ArgumentPathResult.Resolved, ArgumentPath.Parse(path).Resolve(doc.RootElement, out var text));
        Assert.Equal(expected, text);
    }

    [Theory]
    [InlineData("{\"it's\":\"q\"}", "$['it\\'s']", "q")]
    [InlineData("{\"a\\\\b\":\"bs\"}", "$['a\\\\b']", "bs")]
    public void Resolve_EscapedQuotedNames(string json, string path, string expected)
    {
        using var doc = JsonDocument.Parse(json);
        Assert.Equal(ArgumentPathResult.Resolved, ArgumentPath.Parse(path).Resolve(doc.RootElement, out var text));
        Assert.Equal(expected, text);
    }

    [Fact]
    public void Resolve_CompactText_KeepsRawCharacters()
    {
        using var doc = JsonDocument.Parse("{\"o\":{\"k\":\"<a&b>\\u00e9+'\"}}");
        Assert.Equal(ArgumentPathResult.Resolved, ArgumentPath.Parse("$.o").Resolve(doc.RootElement, out var text));
        Assert.Equal("{\"k\":\"<a&b>\u00e9+'\"}", text);
    }

    [Theory]
    [InlineData("$.missing")]
    [InlineData("$.a['b c'][2]")]
    [InlineData("$.a[0]")]
    [InlineData("$.a['b c']['x']")]
    [InlineData("$.n")]
    public void Resolve_Unresolved_ReturnsNotFound(string path)
    {
        using var doc = JsonDocument.Parse("{\"a\":{\"b c\":[10,\"x\"]},\"n\":null}");
        Assert.Equal(ArgumentPathResult.NotFound, ArgumentPath.Parse(path).Resolve(doc.RootElement, out var text));
        Assert.Equal(string.Empty, text);
    }

    [Theory]
    [InlineData("")]
    [InlineData("m")]
    [InlineData("$")]
    [InlineData("$..m")]
    [InlineData("$.*")]
    [InlineData("$[-1]")]
    [InlineData("$[?(@.a)]")]
    [InlineData("$.a[0:2]")]
    [InlineData("$['unterminated")]
    [InlineData("$['bad\\x']")]
    [InlineData("$['trail\\']")]
    public void Parse_BadSyntax_ThrowsNamingPath(string path)
    {
        var ex = Assert.Throws<ArgumentException>(() => ArgumentPath.Parse(path));
        Assert.Contains(path, ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Resolve_NonContainerArguments_NeverThrow()
    {
        var path = ArgumentPath.Parse("$.m");
        Assert.Equal(ArgumentPathResult.NotFound, path.Resolve(default, out _));
        using var doc = JsonDocument.Parse("\"raw\"");
        Assert.Equal(ArgumentPathResult.NotFound, path.Resolve(doc.RootElement, out _));
    }

    [Theory]
    [InlineData("{\"m\":\"\\ud800\"}", "$.m")]
    [InlineData("{\"\\ud800\":1,\"m\":\"x\"}", "$.m")]
    [InlineData("{\"o\":{\"k\":\"\\ud800\"}}", "$.o")]
    [InlineData("{\"o\":{\"\\udc00\":1}}", "$.o")]
    public void Resolve_LoneSurrogate_ReturnsUnreadable(string json, string path)
    {
        using var doc = JsonDocument.Parse(json);
        Assert.Equal(ArgumentPathResult.Unreadable, ArgumentPath.Parse(path).Resolve(doc.RootElement, out _));
    }

    [Theory]
    [InlineData("{\"m\":\"a\",\"m\":\"b\"}", "$.m")]
    [InlineData("{\"a\":{},\"a\":{\"m\":\"x\"}}", "$.a.m")]
    [InlineData("{\"a\":[{\"m\":1,\"m\":2}]}", "$.a[0].m")]
    public void Resolve_DuplicateKeyOnPath_ReturnsDuplicateKey(string json, string path)
    {
        using var doc = JsonDocument.Parse(json);
        Assert.Equal(ArgumentPathResult.DuplicateKey, ArgumentPath.Parse(path).Resolve(doc.RootElement, out _));
    }

    [Fact]
    public void Resolve_DuplicateKeyOffPath_IsIgnored()
    {
        using var doc = JsonDocument.Parse("{\"x\":1,\"x\":2,\"m\":\"GET\"}");
        Assert.Equal(ArgumentPathResult.Resolved, ArgumentPath.Parse("$.m").Resolve(doc.RootElement, out var text));
        Assert.Equal("GET", text);
    }
}
