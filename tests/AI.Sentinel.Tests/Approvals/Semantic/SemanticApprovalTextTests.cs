using System.Text;
using System.Text.Json;
using AI.Sentinel.Approvals.Conditions;
using AI.Sentinel.Approvals.Semantic;
using Xunit;

namespace AI.Sentinel.Tests.Approvals.Semantic;

public class SemanticApprovalTextTests
{
    private const int Max = 1024;

    private static JsonElement Json(string json) => JsonDocument.Parse(json).RootElement.Clone();

    [Fact]
    public void Bash_DefaultsToCommand()
    {
        var result = SemanticApprovalText.Select("Bash", Json("""{"command":"rm -rf /","description":"x"}"""), null, Max);

        var item = Assert.Single(result);
        Assert.Equal("$.command", item.Path);
        Assert.Equal("rm -rf /", item.Text);
        Assert.False(item.Truncated);
    }

    [Theory]
    [InlineData("bash")]
    [InlineData("powershell")]
    public void CopilotBash_And_Powershell_DefaultToCommand(string tool)
    {
        var result = SemanticApprovalText.Select(tool, Json("""{"command":"Remove-Item -Recurse C:\\data"}"""), null, Max);

        var item = Assert.Single(result);
        Assert.Equal("$.command", item.Path);
        Assert.Equal("Remove-Item -Recurse C:\\data", item.Text);
    }

    [Fact]
    public void ToolNameMatchIsCaseSensitive()
    {
        var result = SemanticApprovalText.Select("BASH", Json("""{"command":"ls"}"""), null, Max);

        Assert.Equal("$", Assert.Single(result).Path);
    }

    [Fact]
    public void OtherTool_UsesCompactJson()
    {
        var result = SemanticApprovalText.Select("db_query", Json("""{ "sql": "DROP TABLE a", "n": 1 }"""), null, Max);

        var item = Assert.Single(result);
        Assert.Equal("$", item.Path);
        Assert.Equal("""{"sql":"DROP TABLE a","n":1}""", item.Text);
    }

    [Fact]
    public void ExplicitPaths_EachYieldOneText()
    {
        var paths = new[] { ArgumentPath.Parse("$.url"), ArgumentPath.Parse("$.body.sql"), ArgumentPath.Parse("$.n") };
        var result = SemanticApprovalText.Select("Bash", Json("""{"url":"https://x/y","body":{"sql":"DROP TABLE a"},"n":7,"command":"ls"}"""), paths, Max);

        Assert.Equal(new[] { "$.url", "$.body.sql", "$.n" }, result.Select(r => r.Path).ToArray());
        Assert.Equal(new[] { "https://x/y", "DROP TABLE a", "7" }, result.Select(r => r.Text).ToArray());
    }

    [Fact]
    public void MissingAndNullPaths_YieldNothing()
    {
        var paths = new[] { ArgumentPath.Parse("$.absent"), ArgumentPath.Parse("$.nothing") };

        Assert.Empty(SemanticApprovalText.Select("t", Json("""{"nothing":null}"""), paths, Max));
        Assert.Empty(SemanticApprovalText.Select("Bash", Json("""{"other":1}"""), null, Max));
    }

    [Fact]
    public void BlankAndDuplicateTexts_AreDropped()
    {
        var paths = new[] { ArgumentPath.Parse("$.a"), ArgumentPath.Parse("$.b"), ArgumentPath.Parse("$.c") };
        var result = SemanticApprovalText.Select("t", Json("""{"a":"same","b":"same","c":"   "}"""), paths, Max);

        Assert.Equal("$.a", Assert.Single(result).Path);
    }

    [Fact]
    public void StringArgs_YieldRawText()
    {
        var result = SemanticApprovalText.Select("t", Json("\"DROP DATABASE x\""), null, Max);

        var item = Assert.Single(result);
        Assert.Equal("$", item.Path);
        Assert.Equal("DROP DATABASE x", item.Text);
    }

    [Fact]
    public void UndefinedArgs_YieldNothing()
    {
        Assert.Empty(SemanticApprovalText.Select("t", default, null, Max));
    }

    [Fact]
    public void LargeText_TruncatedOnUtf8Boundary()
    {
        const int cap = 1000;
        // 998 ASCII bytes, then a 4-byte emoji straddling the cap, then a long tail (about 2 MB).
        var text = new string('a', 998) + "\U0001F600" + new string('b', 2_000_000);
        var args = JsonSerializer.SerializeToElement(new Dictionary<string, string>(StringComparer.Ordinal) { ["command"] = text });

        var item = Assert.Single(SemanticApprovalText.Select("Bash", args, null, cap));

        Assert.True(item.Truncated);
        var bytes = new UTF8Encoding(false, throwOnInvalidBytes: true).GetBytes(item.Text);
        Assert.True(bytes.Length <= cap);
        Assert.Equal(new string('a', 998), item.Text);
        Assert.DoesNotContain("\uFFFD", item.Text, StringComparison.Ordinal);
    }

    [Fact]
    public void TextWithinCap_NotTruncated()
    {
        var item = Assert.Single(SemanticApprovalText.Select("Bash", Json("""{"command":"abcd"}"""), null, 4));

        Assert.False(item.Truncated);
        Assert.Equal("abcd", item.Text);
    }

    [Fact]
    public void WhitespacePaddedText_IsTrimmedBeforeTruncation()
    {
        var args = JsonSerializer.SerializeToElement(new Dictionary<string, string>(StringComparer.Ordinal) { ["command"] = new string(' ', 5000) + "rm -rf /" });

        var item = Assert.Single(SemanticApprovalText.Select("Bash", args, null, 100));

        Assert.Equal("rm -rf /", item.Text);
        Assert.False(item.Truncated);
    }

    [Fact]
    public void DuplicateDroppedAfterTruncation_MarksKeptEntryTruncated()
    {
        var paths = new[] { ArgumentPath.Parse("$.a"), ArgumentPath.Parse("$.b") };
        var args = Json("""{"a":"abcd","b":"abcdefgh"}""");

        var item = Assert.Single(SemanticApprovalText.Select("t", args, paths, 4));

        Assert.Equal("$.a", item.Path);
        Assert.Equal("abcd", item.Text);
        Assert.True(item.Truncated);
    }

    [Fact]
    public void NullRoot_YieldsNothing() =>
        Assert.Empty(SemanticApprovalText.Select("t", Json("null"), null, Max));

    [Theory]
    [InlineData("42", "42")]
    [InlineData("true", "true")]
    [InlineData("false", "false")]
    public void NumberAndBooleanRoots_YieldRawToken(string json, string expected)
    {
        var item = Assert.Single(SemanticApprovalText.Select("Bash", Json(json), null, Max));

        Assert.Equal("$", item.Path);
        Assert.Equal(expected, item.Text);
    }

    [Fact]
    public void ArrayRoot_YieldsCompactJson()
    {
        var item = Assert.Single(SemanticApprovalText.Select("t", Json("""[ "a", 1 ]"""), null, Max));

        Assert.Equal("$", item.Path);
        Assert.Equal("""["a",1]""", item.Text);
    }

    [Theory]
    [InlineData("\u00e9", 2)]
    [InlineData("\u20ac", 3)]
    public void MultiByteChar_StraddlingCap_IsNotSplit(string escaped, int size)
    {
        var ch = JsonSerializer.Deserialize<string>($"\"{escaped}\"")!;
        var args = JsonSerializer.SerializeToElement(new Dictionary<string, string>(StringComparer.Ordinal) { ["command"] = "aaaa" + ch + "zz" });

        var item = Assert.Single(SemanticApprovalText.Select("Bash", args, null, 4 + size - 1));

        Assert.Equal("aaaa", item.Text);
        Assert.True(item.Truncated);

        var exact = Assert.Single(SemanticApprovalText.Select("Bash", args, null, 4 + size));
        Assert.Equal("aaaa" + ch, exact.Text);
        Assert.True(exact.Truncated);
    }

    [Fact]
    public void TextExactlyAtCap_NotTruncated()
    {
        var args = Json("""{"command":"a\u20acb"}""");

        var item = Assert.Single(SemanticApprovalText.Select("Bash", args, null, 5));

        Assert.Equal("a\u20acb", item.Text);
        Assert.False(item.Truncated);
    }

    [Fact]
    public void DefaultExamples_NonEmpty_NoBlanks_NoDuplicates()
    {
        var examples = SemanticApprovalExamples.Default;

        Assert.InRange(examples.Length, 20, 40);
        Assert.All(examples, e => Assert.False(string.IsNullOrWhiteSpace(e)));
        Assert.Equal(examples.Length, examples.Distinct(StringComparer.Ordinal).Count());
        Assert.InRange(SemanticApprovalExamples.DefaultThreshold, 0.01f, 1f);
    }
}
