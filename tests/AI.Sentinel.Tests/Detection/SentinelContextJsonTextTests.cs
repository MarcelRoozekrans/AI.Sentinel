using System.Text.Json;
using AI.Sentinel.Detection;
using Microsoft.Extensions.AI;
using Xunit;

namespace AI.Sentinel.Tests.Detection;

/// <summary>#441. Tool calls and JsonElement results are read as JSON, which escapes every character outside the
/// Basic Multilingual Plane; detectors must see those characters themselves.</summary>
public class SentinelContextJsonTextTests
{
    private static string Json(string value) =>
        JsonSerializer.Serialize(value, AIJsonUtilities.DefaultOptions.GetTypeInfo(typeof(string)));

    public static TheoryData<string> Values => new()
    {
        "plain ascii",
        "quote \" backslash \\ newline \n tab \t nul \0",
        "a literal \\u00e9 in the text",
        "a literal \\\\u00e9 after an escaped backslash",
        "emoji \U0001F600 and accented \u00e9",
        "tags \U000E0049\U000E0067\U000E006E",
        "selectors \U000E0100\U000E01EF\uFE0F",
        "lone high \uD800 surrogate",
        "lone low \uDC00 surrogate",
        "reversed \uDC00\uD800 pair",
        "high surrogate at the end \uD83D",
    };

    [Theory]
    [MemberData(nameof(Values))]
    public void WithNonAsciiUnescaped_IsStillJsonForTheSameValue(string value)
    {
        var json = Json(value);

        // Compared with the escaped JSON, not the input: the serializer itself replaces a lone surrogate with U+FFFD.
        Assert.Equal(Parse(json), Parse(SentinelContext.WithNonAsciiUnescaped(json)));
    }

    private static string? Parse(string json) =>
        (string?)JsonSerializer.Deserialize(json, AIJsonUtilities.DefaultOptions.GetTypeInfo(typeof(string)));

    [Fact]
    public void WithNonAsciiUnescaped_WritesSupplementaryCharactersRaw()
    {
        const string value = "tags \U000E0049\U000E0067 emoji \U0001F600 selector \U000E0100";

        var text = SentinelContext.WithNonAsciiUnescaped(Json(value));

        Assert.Equal($"\"{value}\"", text);
    }

    [Fact]
    public void WithNonAsciiUnescaped_KeepsAsciiAndUnpairedSurrogateEscapes()
    {
        Assert.Equal("\"\\u0022 \\u00\"", SentinelContext.WithNonAsciiUnescaped("\"\\u0022 \\u00\""));
        Assert.Equal("\"\\uD800x\"", SentinelContext.WithNonAsciiUnescaped("\"\\uD800x\""));
        Assert.Equal("\"\\\\u00e9\"", SentinelContext.WithNonAsciiUnescaped("\"\\\\u00e9\""));
    }

    [Fact]
    public void MessageText_ToolCallArguments_CarryTagCharactersRaw()
    {
        const string hidden = "\U000E0049\U000E0067\U000E006E";
        var call = new ChatMessage(ChatRole.Assistant,
            [new FunctionCallContent("c1", "send", new Dictionary<string, object?>(StringComparer.Ordinal) { ["body"] = "hi" + hidden })]);

        Assert.Contains(hidden, SentinelContext.MessageText(call), StringComparison.Ordinal);
    }
}
