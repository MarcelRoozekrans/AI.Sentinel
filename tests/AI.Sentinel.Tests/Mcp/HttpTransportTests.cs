using AI.Sentinel.Mcp;
using Xunit;

namespace AI.Sentinel.Tests.Mcp;

[Collection("NonParallel")] // env var sets
public class HttpTransportTests
{
    [Fact]
    public void IsHttpUrl_HttpScheme_True()
    {
        Assert.True(McpProxy.IsHttpUrl("http://example.com"));
    }

    [Fact]
    public void IsHttpUrl_HttpsScheme_True()
    {
        Assert.True(McpProxy.IsHttpUrl("https://example.com/mcp"));
    }

    [Fact]
    public void IsHttpUrl_FilePath_False()
    {
        Assert.False(McpProxy.IsHttpUrl("/usr/bin/some-server"));
    }

    [Fact]
    public void IsHttpUrl_RelativePath_False()
    {
        Assert.False(McpProxy.IsHttpUrl("./my-server"));
    }

    [Fact]
    public void IsHttpUrl_Garbage_False()
    {
        Assert.False(McpProxy.IsHttpUrl("foo bar"));
    }

    [Fact]
    public void ParseHttpHeaders_Null_ReturnsEmpty()
    {
        Assert.Empty(McpProxy.ParseHttpHeaders(null));
    }

    [Fact]
    public void ParseHttpHeaders_EmptyString_ReturnsEmpty()
    {
        Assert.Empty(McpProxy.ParseHttpHeaders(""));
    }

    [Fact]
    public void ParseHttpHeaders_SinglePair_Parsed()
    {
        var d = McpProxy.ParseHttpHeaders("Authorization=Bearer xyz");
        Assert.Equal("Bearer xyz", d["Authorization"]);
        Assert.Single(d);
    }

    [Fact]
    public void ParseHttpHeaders_MultiplePairs_Parsed()
    {
        var d = McpProxy.ParseHttpHeaders("Authorization=Bearer xyz;X-Tenant=acme");
        Assert.Equal("Bearer xyz", d["Authorization"]);
        Assert.Equal("acme",        d["X-Tenant"]);
        Assert.Equal(2, d.Count);
    }

    [Fact]
    public void ParseHttpHeaders_TrimsWhitespace()
    {
        var d = McpProxy.ParseHttpHeaders(" Authorization = Bearer xyz ; X-Tenant = acme ");
        Assert.Equal("Bearer xyz", d["Authorization"]);
        Assert.Equal("acme",        d["X-Tenant"]);
    }

    [Fact]
    public void ParseHttpHeaders_MalformedPairSkipped()
    {
        // No `=` in pair → skipped silently
        var d = McpProxy.ParseHttpHeaders("Authorization=Bearer xyz;malformed;X-Tenant=acme");
        Assert.Equal(2, d.Count);
        Assert.Equal("Bearer xyz", d["Authorization"]);
        Assert.Equal("acme",        d["X-Tenant"]);
    }
}
