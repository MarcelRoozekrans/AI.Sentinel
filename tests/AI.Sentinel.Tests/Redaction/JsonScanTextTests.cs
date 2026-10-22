using System.Text.Json;
using System.Text.Json.Nodes;
using AI.Sentinel.Redaction;
using Xunit;

namespace AI.Sentinel.Tests.Redaction;

public class JsonScanTextTests
{
    // The redaction renders one member exactly as the scan renders it inside a document.
    [Theory]
    [InlineData("password", "hunter2")]
    [InlineData("pass\"word", "a\"b\\c")]
    [InlineData("note", "line1\nline2 <é> & 'x'")]
    [InlineData("", "")]
    public void RenderMember_IsTheMemberOfTheScanText(string name, string value)
    {
        var json = new JsonObject { [name] = value }.ToJsonString();
        using var doc = JsonDocument.Parse(json);
        var scan = HostContent.FromJson(doc.RootElement).ScanText();

        Assert.Equal(scan[1..^1], JsonScanText.RenderMember(name, value).Text);
    }

    // "k": "a\"b" — offsets: the value starts at 6 with a, 7 is the added backslash, 8 the quote it escapes,
    // 9 is b and 10 the closing quote. The value itself is a"b.
    [Theory]
    [InlineData(6, 7, 0, 1)]   // a, inside the value
    [InlineData(7, 9, 1, 2)]   // starts on the added backslash
    [InlineData(6, 8, 0, 2)]   // ends on the added backslash, which stands for the quote it escapes
    [InlineData(8, 10, 1, 3)]  // starts just after the added backslash
    [InlineData(9, 10, 2, 3)]  // after the escape
    [InlineData(2, 8, 0, 2)]   // starts in the key, before the value
    [InlineData(0, 11, 0, 3)]  // the whole member
    public void TryMapToValue_MapsOntoTheValue(int start, int end, int from, int to)
    {
        var member = JsonScanText.RenderMember("k", "a\"b");
        Assert.Equal("\"k\": \"a\\\"b\"", member.Text);

        Assert.True(member.TryMapToValue(start, end, out var f, out var t));
        Assert.Equal((from, to), (f, t));
    }

    [Theory]
    [InlineData(1, 2)]   // the key only
    [InlineData(0, 6)]   // the key, the colon and the opening quote
    [InlineData(10, 11)] // the closing quote, after the value
    public void TryMapToValue_SpanWithNoPartInTheValue_IsFalse(int start, int end)
    {
        Assert.False(JsonScanText.RenderMember("k", "a\"b").TryMapToValue(start, end, out _, out _));
    }

    // "k": "a\"b\\c\"d", three added backslashes at 7, 10 and 13, so the escapes before an offset are counted
    // by the binary search: a at 6, its escaped quote at 8, b at 9, the escaped backslash at 11, c at 12, the
    // escaped quote at 14, d at 15. The value itself is a"b\c"d.
    [Theory]
    [InlineData(9, 10, 2, 3)]   // b, after one escape
    [InlineData(10, 12, 3, 4)]  // the second escape and the backslash it stands for
    [InlineData(11, 13, 3, 5)]  // starts after the second escape, ends on the third
    [InlineData(12, 13, 4, 5)]  // c, after two escapes
    [InlineData(13, 16, 5, 7)]  // starts on the third escape
    [InlineData(15, 16, 6, 7)]  // d, after all three
    [InlineData(6, 16, 0, 7)]   // the whole value
    public void TryMapToValue_SeveralEscapes_MapsOntoTheValue(int start, int end, int from, int to)
    {
        var member = JsonScanText.RenderMember("k", "a\"b\\c\"d");
        Assert.Equal("\"k\": \"a\\\"b\\\\c\\\"d\"", member.Text);

        Assert.True(member.TryMapToValue(start, end, out var f, out var t));
        Assert.Equal((from, to), (f, t));
    }

    [Fact]
    public void TryMapToValue_NoEscapes_IsAnOffset()
    {
        var member = JsonScanText.RenderMember("password", "hunter2");

        Assert.True(member.TryMapToValue(member.Text.IndexOf("hunter2", StringComparison.Ordinal), member.Text.Length - 1, out var from, out var to));
        Assert.Equal((0, 7), (from, to));
    }
}
