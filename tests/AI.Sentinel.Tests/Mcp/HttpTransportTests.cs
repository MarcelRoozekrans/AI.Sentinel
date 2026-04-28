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

    [Fact]
    public void ParseHttpHeaders_EqualsInValue_PreservedAfterFirstEquals()
    {
        // IndexOf('=') splits on the first '=' only; trailing '=' chars (e.g. base64
        // padding in Basic auth) must be retained verbatim in the value.
        var d = McpProxy.ParseHttpHeaders("Authorization=Basic abc==");
        Assert.Single(d);
        Assert.Equal("Basic abc==", d["Authorization"]);
    }

    [Fact]
    public void ParseHttpHeaders_DuplicateHeaderName_LastWins()
    {
        // Dictionary indexer assignment means the last occurrence wins.
        // Documented here so a future swap to TryAdd / ThrowIfDuplicate is a deliberate choice.
        var d = McpProxy.ParseHttpHeaders("X-Tenant=acme;X-Tenant=corp");
        Assert.Single(d);
        Assert.Equal("corp", d["X-Tenant"]);
    }

    [Fact]
    public void ParseHttpHeaders_CRLFInjection_HeaderValuePreservedRaw()
    {
        // Splitter is `;` only — CRLF inside a value does NOT spawn a second header.
        // This locks in the current safe behavior: a CRLF in the value stays in the value
        // (and downstream HttpClient rejects CRLF in header values, blocking injection at
        // the transport layer). If a future "improvement" splits on CRLF here, this test
        // fails loudly — that would be a CRLF-injection regression.
        const string injected = "X-Foo=value\r\nX-Bar=injected";
        var d = McpProxy.ParseHttpHeaders(injected);

        Assert.Single(d);
        Assert.True(d.ContainsKey("X-Foo"));
        Assert.False(d.ContainsKey("X-Bar"));
        Assert.Equal("value\r\nX-Bar=injected", d["X-Foo"]);
    }
}
