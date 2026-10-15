using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using AI.Sentinel.Detection;
using AI.Sentinel.Detectors.Security;
using AI.Sentinel.Domain;
using AI.Sentinel.Redaction;
using Microsoft.Extensions.AI;
using Xunit;

namespace AI.Sentinel.Tests.Redaction;

public class RedactionSessionTests
{
    private sealed class FakeRedactor(string id, params RedactionSpan[] spans) : IRedactingDetector
    {
        public DetectorId Id { get; } = new(id);
        public DetectorCategory Category => DetectorCategory.Security;
        public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct) =>
            ValueTask.FromResult(DetectionResult.Clean(Id));
        public IReadOnlyList<RedactionSpan> FindSpans(string text) => spans;
    }

    private sealed class ThrowingRedactor : IRedactingDetector
    {
        public DetectorId Id { get; } = new("TST-01");
        public DetectorCategory Category => DetectorCategory.Security;
        public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct) =>
            ValueTask.FromResult(DetectionResult.Clean(Id));
        public IReadOnlyList<RedactionSpan> FindSpans(string text) =>
            throw new RegexMatchTimeoutException();
    }

    private static RedactionSession Pii() => new([new PiiLeakageDetector()]);

    [Fact]
    public void SameValueTwice_GetsSamePlaceholder()
    {
        var session = Pii();
        Assert.Equal("[EMAIL_1] and [EMAIL_1]", session.Redact("jan@acme.nl and jan@acme.nl"));
        Assert.Equal("again [EMAIL_1]", session.Redact("again jan@acme.nl"));
    }

    [Fact]
    public void TwoEmails_NumberedPerType()
    {
        var session = Pii();
        var result = session.Redact("a@acme.nl, b@acme.nl and NL91ABNA0417164300");
        Assert.Equal("[EMAIL_1], [EMAIL_2] and [IBAN_1]", result);
        Assert.True(session.HasRedactions);
    }

    [Fact]
    public void ExistingPlaceholderInInput_NumberingSkipsPastIt_AndRestoreLeavesItLiteral()
    {
        var session = Pii();
        var redacted = session.Redact("[EMAIL_1] and jan@acme.nl");
        Assert.Equal("[EMAIL_1] and [EMAIL_2]", redacted);
        Assert.Equal("[EMAIL_1] and jan@acme.nl", session.Restore(redacted));
    }

    [Fact]
    public void OverlappingSpans_LongestWins()
    {
        var first = new FakeRedactor("TST-01", new RedactionSpan(0, 6, "X"), new RedactionSpan(10, 2, "Z"));
        var second = new FakeRedactor("TST-02", new RedactionSpan(3, 6, "Y"));
        var session = new RedactionSession([first, second]);
        // X [0,6) and Y [3,9) partially overlap: one union span typed X (tie, started first).
        Assert.Equal("[X_1]j[Z_1]", session.Redact("abcdefghijkl"));
    }

    [Fact]
    public void OverlappingSpans_LongerTypeWinsAndContainedAbsorbed()
    {
        var a = new FakeRedactor("TST-01", new RedactionSpan(0, 4, "SHORT"));
        var b = new FakeRedactor("TST-02", new RedactionSpan(2, 8, "LONG"), new RedactionSpan(3, 2, "INNER"));
        var session = new RedactionSession([a, b]);
        Assert.Equal("[LONG_1]!", session.Redact("0123456789!"));
        var counts = session.CountsByDetector;
        Assert.Single(counts);
        Assert.Equal(1, counts["TST-02"]["LONG"]);
    }

    [Fact]
    public void DetectorException_Propagates()
    {
        var session = new RedactionSession([new ThrowingRedactor()]);
        Assert.Throws<RegexMatchTimeoutException>(() => session.Redact("anything"));
    }

    [Theory]
    [InlineData("[email_1]")]
    [InlineData("[EMAIL_1")]
    [InlineData("EMAIL_1")]
    [InlineData("[EMAIL_01]")]
    [InlineData("[EMAIL_2]")]
    public void MangledPlaceholder_NotRestored(string mangled)
    {
        var session = Pii();
        Assert.Equal("[EMAIL_1]", session.Redact("jan@acme.nl"));
        Assert.Equal(mangled, session.Restore(mangled));
    }

    [Fact]
    public void ValueSplitAcrossParts_EachPartHandledAlone_NoThrow()
    {
        var session = Pii();
        var messages = new List<ChatMessage>
        {
            new(ChatRole.User, [new TextContent("mail jan@ac"), new TextContent("me.nl please")]),
        };
        var result = session.Redact(messages);
        var parts = result[0].Contents.OfType<TextContent>().ToArray();
        Assert.Equal("mail jan@ac", parts[0].Text);
        Assert.Equal("me.nl please", parts[1].Text);
    }

    [Fact]
    public void FunctionCallArguments_NestedJsonStrings_Redacted()
    {
        var session = Pii();
        var json = JsonDocument.Parse("""{"to":"jan@acme.nl","cc":["b@acme.nl",3],"n":{"k":"x jan@acme.nl"},"flag":true}""").RootElement;
        var call = new FunctionCallContent("c1", "send", new Dictionary<string, object?>(StringComparer.Ordinal) { ["body"] = json, ["plain"] = "jan@acme.nl" });
        var result = session.Redact([new ChatMessage(ChatRole.Assistant, [call])]);
        var args = ((FunctionCallContent)result[0].Contents[0]).Arguments!;
        Assert.Equal("[EMAIL_1]", args["plain"]);
        Assert.Equal("""{"to":"[EMAIL_1]","cc":["[EMAIL_2]",3],"n":{"k":"x [EMAIL_1]"},"flag":true}""",
            ((JsonElement)args["body"]!).GetRawText());
    }

    [Fact]
    public void FunctionResult_JsonElementString_Redacted()
    {
        var session = Pii();
        var element = JsonDocument.Parse("\"reach jan@acme.nl\"").RootElement;
        var result = session.Redact([new ChatMessage(ChatRole.Tool, [new FunctionResultContent("c1", element)])]);
        var redacted = (JsonElement)((FunctionResultContent)result[0].Contents[0]).Result!;
        Assert.Equal("reach [EMAIL_1]", redacted.GetString());
        Assert.Equal("reach [EMAIL_1]", session.RedactResult("reach jan@acme.nl"));
        Assert.Equal(42, session.RedactResult(42));
        Assert.Null(session.RedactResult(null));
    }

    [Fact]
    public void Restore_FunctionCallArguments_RealValuesBack()
    {
        var session = Pii();
        session.Redact("jan@acme.nl");
        var call = new FunctionCallContent("c1", "send", new Dictionary<string, object?>(StringComparer.Ordinal) { ["to"] = "[EMAIL_1]", ["n"] = 5 });
        var restored = session.Restore([new ChatMessage(ChatRole.Assistant, [call, new TextContent("hi [EMAIL_1]")])]);
        var args = ((FunctionCallContent)restored[0].Contents[0]).Arguments!;
        Assert.Equal("jan@acme.nl", args["to"]);
        Assert.Equal(5, args["n"]);
        Assert.Equal("hi jan@acme.nl", ((TextContent)restored[0].Contents[1]).Text);

        var fnArgs = session.Restore(new AIFunctionArguments(StringComparer.Ordinal) { ["to"] = "[EMAIL_1]" });
        Assert.Equal("jan@acme.nl", fnArgs["to"]);
    }

    [Fact]
    public void Redact_DoesNotMutateInput()
    {
        var session = Pii();
        var text = new TextContent("jan@acme.nl");
        var call = new FunctionCallContent("c1", "f", new Dictionary<string, object?>(StringComparer.Ordinal) { ["a"] = "jan@acme.nl" });
        var input = new List<ChatMessage> { new(ChatRole.User, [text, call]) };
        var output = session.Redact(input);
        Assert.NotSame(input[0], output[0]);
        Assert.Equal("jan@acme.nl", text.Text);
        Assert.Equal("jan@acme.nl", call.Arguments!["a"]);
        Assert.Equal("[EMAIL_1]", ((TextContent)output[0].Contents[0]).Text);
    }

    [Fact]
    public void CountsByDetector_ReportsCountsOnly()
    {
        var session = new RedactionSession([new PiiLeakageDetector(), new CredentialExposureDetector()]);
        session.Redact("jan@acme.nl and jan@acme.nl and NL91ABNA0417164300");
        var counts = session.CountsByDetector;
        Assert.Equal(2, counts["SEC-23"]["EMAIL"]);
        Assert.Equal(1, counts["SEC-23"]["IBAN"]);
        Assert.DoesNotContain("acme", System.Text.Json.JsonSerializer.Serialize(counts), StringComparison.Ordinal);
    }

    [Fact]
    public async Task ConcurrentUse_IsConsistent()
    {
        var session = Pii();
        var tasks = new Task<string>[32];
        for (var i = 0; i < tasks.Length; i++)
        {
            var email = $"user{i % 8}@acme.nl";
            tasks[i] = Task.Run(() => session.Restore(session.Redact(email)));
        }
        var results = await Task.WhenAll(tasks);
        for (var i = 0; i < results.Length; i++)
        {
            Assert.Equal($"user{i % 8}@acme.nl", results[i]);
        }
        Assert.Equal(nameof(RedactionSession), session.ToString());
        Assert.Equal(32, session.CountsByDetector["SEC-23"]["EMAIL"]);
    }

    private sealed class Owner
    {
        public string Name { get; set; } = "";
        public string[] Emails { get; set; } = [];
    }

    private sealed class Unserializable
    {
        public string Boom => throw new InvalidOperationException("boom jan@acme.nl");
    }

    private sealed class FormatGetter
    {
        public string Boom => throw new FormatException("bad jan@acme.nl");
    }

    private sealed class ServiceCollectionStub : IServiceProvider
    {
        public object? GetService(Type serviceType) => null;
    }

    [Fact]
    public void CrossMessage_LiteralInLaterMessage_IsReservedBeforeMinting()
    {
        var session = Pii();
        var result = session.Redact(
        [
            new ChatMessage(ChatRole.User, "mail jan@acme.nl"),
            new ChatMessage(ChatRole.User, "literal [EMAIL_1]"),
        ]);
        Assert.Equal("mail [EMAIL_2]", result[0].Text);
        Assert.Equal("literal [EMAIL_1]", result[1].Text);
        Assert.Equal("literal [EMAIL_1]", session.Restore("literal [EMAIL_1]"));
        Assert.Equal("mail jan@acme.nl", session.Restore(result[0].Text));
    }

    [Fact]
    public void CrossMessage_LiteralInLaterToolArgument_IsReserved()
    {
        var session = Pii();
        var call = new FunctionCallContent("c", "f", new Dictionary<string, object?>(StringComparer.Ordinal) { ["a"] = "[EMAIL_1]" });
        var result = session.Redact([new ChatMessage(ChatRole.User, "jan@acme.nl"), new ChatMessage(ChatRole.Assistant, [call])]);
        Assert.Equal("[EMAIL_2]", result[0].Text);
    }

    [Fact]
    public void RedactResult_AIContent_IsRedacted()
    {
        var session = Pii();
        var single = (TextContent)session.RedactResult(new TextContent("owner: jan@acme.nl"))!;
        Assert.Equal("owner: [EMAIL_1]", single.Text);

        var list = (IEnumerable<AIContent>)session.RedactResult(new List<AIContent> { new TextContent("a b@acme.nl") })!;
        Assert.Equal("a [EMAIL_2]", ((TextContent)Assert.Single(list)).Text);
    }

    [Fact]
    public void RedactResult_JsonNodeAndPocoAndCollections_AreRedactedAsJson()
    {
        var session = Pii();
        var node = (JsonElement)session.RedactResult(JsonNode.Parse("""{"m":"jan@acme.nl"}"""))!;
        Assert.Equal("""{"m":"[EMAIL_1]"}""", node.GetRawText());

        var poco = (JsonElement)session.RedactResult(new Owner { Name = "x", Emails = ["jan@acme.nl"] })!;
        Assert.Contains("[EMAIL_1]", poco.GetRawText(), StringComparison.Ordinal);
        Assert.DoesNotContain("acme", poco.GetRawText(), StringComparison.Ordinal);

        var dict = (JsonElement)session.RedactResult(new Dictionary<string, string>(StringComparer.Ordinal) { ["k"] = "jan@acme.nl" })!;
        Assert.Equal("""{"k":"[EMAIL_1]"}""", dict.GetRawText());

        var array = (List<object?>)session.RedactResult(new List<string> { "jan@acme.nl", "z" })!;
        Assert.Equal("[EMAIL_1]", array[0]);
        Assert.Equal("z", array[1]);
    }

    [Fact]
    public void RedactResult_Unserializable_FailsClosedWithoutValueInMessage()
    {
        var session = Pii();
        var ex = Assert.Throws<InvalidOperationException>(() => session.RedactResult(new Unserializable()));
        Assert.DoesNotContain("acme", ex.ToString(), StringComparison.Ordinal);
        Assert.Null(ex.InnerException);
    }

    [Fact]
    public void EntityTypes_AreNormalized()
    {
        var a = new FakeRedactor("TST-01", new RedactionSpan(0, 4, "Email"), new RedactionSpan(10, 4, "tax-id"));
        var b = new FakeRedactor("TST-02", new RedactionSpan(5, 4, "EMAIL"), new RedactionSpan(15, 4, "x1"));
        var session = new RedactionSession([a, b]);
        var redacted = session.Redact("aaaa bbbb cccc dddd");
        Assert.Equal("[EMAIL_1] [EMAIL_2] [TAX_ID_1] [X1_1]", redacted);
        Assert.Equal("aaaa bbbb cccc dddd", session.Restore(redacted));
    }

    [Fact]
    public void JsonPropertyNames_AreRedactedAndRestored()
    {
        var session = Pii();
        var json = JsonDocument.Parse("""{"jan@acme.nl":{"x":1}}""").RootElement;
        var call = new FunctionCallContent("c", "f", new Dictionary<string, object?>(StringComparer.Ordinal) { ["m"] = json });
        var redacted = session.Redact([new ChatMessage(ChatRole.Assistant, [call])]);
        var element = (JsonElement)((FunctionCallContent)redacted[0].Contents[0]).Arguments!["m"]!;
        Assert.Equal("""{"[EMAIL_1]":{"x":1}}""", element.GetRawText());

        var restored = session.Restore(new List<ChatMessage>(redacted));
        var back = (JsonElement)((FunctionCallContent)restored[0].Contents[0]).Arguments!["m"]!;
        Assert.Equal("""{"jan@acme.nl":{"x":1}}""", back.GetRawText());
    }

    [Fact]
    public void ReservedNumberNearOverflow_IsIgnored()
    {
        var session = Pii();
        Assert.Equal("[EMAIL_2147483646] [EMAIL_1]", session.Redact("[EMAIL_2147483646] jan@acme.nl"));
    }

    [Fact]
    public void NestedArguments_RedactedAndRestoredKeepingTypes()
    {
        var session = Pii();
        var args = new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["d"] = new Dictionary<string, object?>(StringComparer.Ordinal) { ["jan@acme.nl"] = "jan@acme.nl" },
            ["l"] = new List<object?> { "jan@acme.nl", 7 },
            ["a"] = new object?[] { "jan@acme.nl" },
            ["n"] = JsonNode.Parse("""{"k":"jan@acme.nl"}"""),
        };
        var redacted = session.Redact([new ChatMessage(ChatRole.Assistant, [new FunctionCallContent("c", "f", args)])]);
        var rArgs = ((FunctionCallContent)redacted[0].Contents[0]).Arguments!;
        var rDict = (Dictionary<string, object?>)rArgs["d"]!;
        Assert.Equal("[EMAIL_1]", Assert.Single(rDict).Value);
        Assert.Equal("[EMAIL_1]", Assert.Single(rDict).Key);
        Assert.Equal("""{"k":"[EMAIL_1]"}""", ((JsonElement)rArgs["n"]!).GetRawText());

        // The model echoes the arguments back as CLR containers and JsonNode.
        var echoed = new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["d"] = new Dictionary<string, object?>(StringComparer.Ordinal) { ["[EMAIL_1]"] = "[EMAIL_1]" },
            ["l"] = new List<object?> { "[EMAIL_1]", 7 },
            ["a"] = new object?[] { "[EMAIL_1]" },
            ["n"] = JsonNode.Parse("""{"k":"[EMAIL_1]"}"""),
            ["p"] = new Owner { Name = "[EMAIL_1]" },
        };
        var restored = session.Restore([new ChatMessage(ChatRole.Assistant, [new FunctionCallContent("c", "f", echoed)])]);
        var back = ((FunctionCallContent)restored[0].Contents[0]).Arguments!;
        var bDict = Assert.IsType<Dictionary<string, object?>>(back["d"]);
        Assert.Equal("jan@acme.nl", bDict["jan@acme.nl"]);
        Assert.Equal("jan@acme.nl", Assert.IsType<List<object?>>(back["l"])[0]);
        Assert.Equal("jan@acme.nl", Assert.IsType<object[]>(back["a"])[0]);
        Assert.Equal("jan@acme.nl", Assert.IsType<JsonNode>(back["n"], exactMatch: false)["k"]!.GetValue<string>());
        Assert.Equal("[EMAIL_1]", Assert.IsType<Owner>(back["p"]).Name);
    }

    [Fact]
    public void RestoreArguments_RestoresInPlace_KeepingComparerContextAndServices()
    {
        var session = Pii();
        session.Redact("jan@acme.nl");
        var services = new ServiceCollectionStub();
        var context = new Dictionary<object, object?> { ["k"] = "v" };
        var args = new AIFunctionArguments(StringComparer.OrdinalIgnoreCase) { ["To"] = "[EMAIL_1]", Services = services, Context = context };
        var restored = session.Restore(args);
        Assert.Same(args, restored);
        Assert.Equal("jan@acme.nl", restored["TO"]);
        Assert.Same(services, restored.Services);
        Assert.Same(context, restored.Context);
    }

    [Fact]
    public void LaterCall_LiteralEqualToMintedToken_RestoresToTheLiteral()
    {
        var session = Pii();
        Assert.Equal("[EMAIL_1]", session.Redact("jan@acme.nl"));
        var later = (string)session.RedactResult("template [EMAIL_1]")!;
        Assert.Equal("template [EMAIL_2]", later);
        Assert.Equal("template [EMAIL_1]", session.Restore(later));
        Assert.Equal("jan@acme.nl", session.Restore("[EMAIL_1]"));
    }

    [Fact]
    public void RedactResult_ThrowingGetterWithValue_FailsClosedWithoutValue()
    {
        var session = Pii();
        var ex = Assert.Throws<InvalidOperationException>(() => session.RedactResult(new FormatGetter()));
        Assert.DoesNotContain("acme", ex.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void RedactResult_PrimitiveArrays_ByteUntouchedCharRedacted()
    {
        var session = Pii();
        var bytes = new byte[] { 1, 2, 3 };
        Assert.Same(bytes, session.RedactResult(bytes));
        var chars = Assert.IsType<char[]>(session.RedactResult("jan@acme.nl".ToCharArray()));
        Assert.Equal("[EMAIL_1]", new string(chars));
    }

    [Fact]
    public void DataContent_HonoursCharset_AndUnknownCharsetFailsClosed()
    {
        var session = Pii();
        var utf16 = new DataContent(Encoding.Unicode.GetBytes("mail jan@acme.nl"), "text/plain; charset=utf-16");
        var result = session.Redact([new ChatMessage(ChatRole.User, [utf16])]);
        Assert.Equal("mail [EMAIL_1]", Encoding.Unicode.GetString(((DataContent)result[0].Contents[0]).Data.Span));

        var bogus = new DataContent(Encoding.UTF8.GetBytes("jan@acme.nl"), "text/plain; charset=bogus-xyz");
        var ex = Assert.Throws<InvalidOperationException>(() => session.Redact([new ChatMessage(ChatRole.User, [bogus])]));
        Assert.DoesNotContain("acme", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Restore_JsonElementArguments_RealValuesBack()
    {
        var session = Pii();
        session.Redact("jan@acme.nl");
        var json = JsonDocument.Parse("""{"to":["[EMAIL_1]"],"n":1}""").RootElement;
        var call = new FunctionCallContent("c", "f", new Dictionary<string, object?>(StringComparer.Ordinal) { ["p"] = json });
        var restored = session.Restore([new ChatMessage(ChatRole.Assistant, [call])]);
        var back = (JsonElement)((FunctionCallContent)restored[0].Contents[0]).Arguments!["p"]!;
        Assert.Equal("""{"to":["jan@acme.nl"],"n":1}""", back.GetRawText());
    }

    [Fact]
    public void ReasoningAndTextDataContent_AreRedacted_BinaryDataIsNot()
    {
        var session = Pii();
        var bytes = Encoding.UTF8.GetBytes("mail jan@acme.nl");
        var result = session.Redact(
        [
            new ChatMessage(ChatRole.Assistant,
            [
                new TextReasoningContent("think jan@acme.nl"),
                new DataContent(bytes, "text/plain"),
                new DataContent(bytes, "application/octet-stream"),
            ]),
        ]);
        Assert.Equal("think [EMAIL_1]", ((TextReasoningContent)result[0].Contents[0]).Text);
        Assert.Equal("mail [EMAIL_1]", Encoding.UTF8.GetString(((DataContent)result[0].Contents[1]).Data.Span));
        Assert.Equal(bytes, ((DataContent)result[0].Contents[2]).Data.ToArray());
    }

    [Fact]
    public void OutOfRangeSpan_Throws_WithoutValueInMessage()
    {
        var session = new RedactionSession([new FakeRedactor("TST-01", new RedactionSpan(5, 99, "X"))]);
        var ex = Assert.Throws<InvalidOperationException>(() => session.Redact("secret-value"));
        Assert.DoesNotContain("secret", ex.Message, StringComparison.Ordinal);
        Assert.Contains("TST-01", ex.Message, StringComparison.Ordinal);
    }
}
