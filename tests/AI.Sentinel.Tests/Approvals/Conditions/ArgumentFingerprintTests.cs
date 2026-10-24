using System.Text.Json;
using AI.Sentinel.Approvals.Conditions;
using Xunit;

namespace AI.Sentinel.Tests.Approvals.Conditions;

public class ArgumentFingerprintTests
{
    private static string Fingerprint(string json, string toolName = "Bash")
    {
        using var doc = JsonDocument.Parse(json);
        return ArgumentFingerprint.Compute(toolName, doc.RootElement);
    }

    [Fact]
    public void ReorderedKeysAndWhitespace_SameFingerprint()
    {
        Assert.Equal(Fingerprint("{\"b\":1,\"a\":\"x\"}"), Fingerprint("{ \"a\" : \"x\", \"b\" : 1 }"));
    }

    [Fact]
    public void ChangedValue_DifferentFingerprint()
    {
        Assert.NotEqual(Fingerprint("{\"b\":1,\"a\":\"x\"}"), Fingerprint("{\"a\":\"y\",\"b\":1}"), StringComparer.Ordinal);
    }

    [Fact]
    public void NestedReorderedKeys_SameFingerprint()
    {
        Assert.Equal(
            Fingerprint("{\"o\":{\"y\":[1,{\"q\":true,\"p\":null}],\"x\":\"v\"}}"),
            Fingerprint("{\"o\":{\"x\":\"v\",\"y\":[1,{\"p\":null,\"q\":true}]}}"));
    }

    [Fact]
    public void EscapedAndLiteralCharacter_SameFingerprint()
    {
        // The first JSON text holds the literal character, the second the JSON escape sequence.
        Assert.Equal(Fingerprint("{\"a\":\"\u00e9\"}"), Fingerprint("{\"a\":\"\\u00e9\"}"));
    }

    [Fact]
    public void DuplicateKeysInOtherOrder_DifferentFingerprint()
    {
        Assert.NotEqual(Fingerprint("{\"a\":1,\"a\":2}"), Fingerprint("{\"a\":2,\"a\":1}"), StringComparer.Ordinal);
    }

    [Fact]
    public void KnownValue_IsPinned()
    {
        // SHA-256 of UTF-8 "Bash", a 0x00 byte and the canonical text {"a":1}; first 16 bytes, lowercase hex.
        Assert.Equal("e9369becbfdbc5e53540b214cd36aa80", Fingerprint("{ \"a\" : 1 }"));
    }

    [Fact]
    public void OtherToolName_SameArgs_DifferentFingerprint()
    {
        const string json = "{\"path\":\"/etc/prod.conf\"}";
        Assert.NotEqual(
            Fingerprint(json, "mcp__fs__read_file"),
            Fingerprint(json, "mcp__fs__delete_file"),
            StringComparer.Ordinal);
    }

    [Fact]
    public void ToolNameAndArgsBoundary_DoesNotCollide()
    {
        // Moving characters between the tool name and a string-valued argument must change the hash.
        Assert.NotEqual(Fingerprint("\"bc\"", "a"), Fingerprint("\"c\"", "ab"), StringComparer.Ordinal);
    }

    [Fact]
    public void Result_Is32LowercaseHexCharacters()
    {
        var fp = Fingerprint("{\"command\":\"ls\"}");
        Assert.Matches("^[0-9a-f]{32}$", fp);
    }

    [Fact]
    public void UndefinedAndString_DoNotThrow()
    {
        Assert.Matches("^[0-9a-f]{32}$", ArgumentFingerprint.Compute("Bash", default));
        Assert.Matches("^[0-9a-f]{32}$", Fingerprint("\"not json args\""));
        Assert.NotEqual(ArgumentFingerprint.Compute("Bash", default), Fingerprint("\"\""), StringComparer.Ordinal);
    }

    [Theory]
    [InlineData("{\"a\":\"\\ud800\"}")]
    [InlineData("{\"\\ud800\":1}")]
    [InlineData("[{\"k\":[\"\\udc00\"]}]")]
    public void LoneSurrogate_DoesNotThrow_AndIsDeterministic(string json)
    {
        var fp = Fingerprint(json);
        Assert.Matches("^[0-9a-f]{32}$", fp);
        Assert.Equal(fp, Fingerprint(json));
    }

    [Fact]
    public void LoneSurrogate_DifferentValues_DifferentFingerprint()
    {
        Assert.NotEqual(Fingerprint("{\"a\":\"\\ud800\"}"), Fingerprint("{\"a\":\"\\ud801\"}"), StringComparer.Ordinal);
    }
}
