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
    public void TryGetMatchText_ResolvesPath(string path, string expected)
    {
        using var doc = JsonDocument.Parse(Doc);
        Assert.True(ArgumentPath.Parse(path).TryGetMatchText(doc.RootElement, out var text));
        Assert.Equal(expected, text);
    }

    [Theory]
    [InlineData("{\"v\":true}", "$.v", "true")]
    [InlineData("{\"v\":[1, [2,  3], {\"k\": \"z\"}]}", "$.v", "[1,[2,3],{\"k\":\"z\"}]")]
    [InlineData("{\"v\":\"a\\u00e9\"}", "$.v", "aé")]
    public void TryGetMatchText_ValueKinds(string json, string path, string expected)
    {
        using var doc = JsonDocument.Parse(json);
        Assert.True(ArgumentPath.Parse(path).TryGetMatchText(doc.RootElement, out var text));
        Assert.Equal(expected, text);
    }

    [Theory]
    [InlineData("$.missing")]
    [InlineData("$.a['b c'][2]")]
    [InlineData("$.a[0]")]
    [InlineData("$.a['b c']['x']")]
    [InlineData("$.n")]
    public void TryGetMatchText_Unresolved_ReturnsFalse(string path)
    {
        using var doc = JsonDocument.Parse("{\"a\":{\"b c\":[10,\"x\"]},\"n\":null}");
        Assert.False(ArgumentPath.Parse(path).TryGetMatchText(doc.RootElement, out var text));
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
    public void Parse_BadSyntax_ThrowsNamingPath(string path)
    {
        var ex = Assert.Throws<ArgumentException>(() => ArgumentPath.Parse(path));
        Assert.Contains(path, ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void TryGetMatchText_NonContainerArguments_NeverThrow()
    {
        var path = ArgumentPath.Parse("$.m");
        Assert.False(path.TryGetMatchText(default, out _));
        using var doc = JsonDocument.Parse("\"raw\"");
        Assert.False(path.TryGetMatchText(doc.RootElement, out _));
    }
}
