using System.Globalization;
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

    private const string Tag = "abc123";

    private static RedactionSession Pii() => new([new PiiLeakageDetector()], Tag);

    [Fact]
    public void SameValueTwice_GetsSamePlaceholder()
    {
        var session = Pii();
        Assert.Equal("[EMAIL_1_abc123] and [EMAIL_1_abc123]", session.Redact("jan@acme.nl and jan@acme.nl"));
        Assert.Equal("again [EMAIL_1_abc123]", session.Redact("again jan@acme.nl"));
    }

    [Fact]
    public void TwoEmails_NumberedPerType()
    {
        var session = Pii();
        var result = session.Redact("a@acme.nl, b@acme.nl and NL91ABNA0417164300");
        Assert.Equal("[EMAIL_1_abc123], [EMAIL_2_abc123] and [IBAN_1_abc123]", result);
        Assert.True(session.HasRedactions);
    }

    // Placeholder-shaped input is never restored: an untagged literal, or one with another call's tag, is text.
    // Numbering is not affected by it either, since no literal can collide with a token of this call's tag.
    [Fact]
    public void PlaceholderShapedInput_StaysLiteral_AndNumberingStartsAtOne()
    {
        var session = Pii();
        var redacted = session.Redact("[EMAIL_1] [EMAIL_1_zzz999] and jan@acme.nl");
        Assert.Equal("[EMAIL_1] [EMAIL_1_zzz999] and [EMAIL_1_abc123]", redacted);
        Assert.Equal("[EMAIL_1] [EMAIL_1_zzz999] and jan@acme.nl", session.Restore(redacted));
    }

    [Fact]
    public void EveryPlaceholder_CarriesTheSessionTag()
    {
        var session = new RedactionSession([new PiiLeakageDetector()]);
        var redacted = session.Redact("jan@acme.nl and b@acme.nl");
        Assert.Matches(@"^\[EMAIL_1_([a-z][a-z0-9]{5})\] and \[EMAIL_2_\1\]$", redacted);
        Assert.NotEqual(redacted, new RedactionSession([new PiiLeakageDetector()]).Redact("jan@acme.nl and b@acme.nl"), StringComparer.Ordinal);
    }

    [Theory]
    [InlineData("abc12")]
    [InlineData("1bc123")]
    [InlineData("ABC123")]
    [InlineData("abc_23")]
    public void MalformedTag_IsRejected(string tag)
    {
        Assert.Throws<ArgumentException>(() => new RedactionSession([new PiiLeakageDetector()], tag));
    }


    [Fact]
    public void OverlappingSpans_LongestWins()
    {
        var first = new FakeRedactor("TST-01", new RedactionSpan(0, 6, "X"), new RedactionSpan(10, 2, "Z"));
        var second = new FakeRedactor("TST-02", new RedactionSpan(3, 6, "Y"));
        var session = new RedactionSession([first, second], Tag);
        // X [0,6) and Y [3,9) partially overlap: one union span typed X (tie, started first).
        Assert.Equal("[X_1_abc123]j[Z_1_abc123]", session.Redact("abcdefghijkl"));
    }

    [Fact]
    public void OverlappingSpans_LongerTypeWinsAndContainedAbsorbed()
    {
        var a = new FakeRedactor("TST-01", new RedactionSpan(0, 4, "SHORT"));
        var b = new FakeRedactor("TST-02", new RedactionSpan(2, 8, "LONG"), new RedactionSpan(3, 2, "INNER"));
        var session = new RedactionSession([a, b], Tag);
        Assert.Equal("[LONG_1_abc123]!", session.Redact("0123456789!"));
        var counts = session.CountsByDetector;
        Assert.Single(counts);
        Assert.Equal(1, counts["TST-02"]["LONG"]);
    }

    [Fact]
    public void DetectorException_Propagates()
    {
        var session = new RedactionSession([new ThrowingRedactor()], Tag);
        Assert.Throws<RegexMatchTimeoutException>(() => session.Redact("anything"));
    }

    [Theory]
    [InlineData("[email_1_abc123]")]
    [InlineData("[EMAIL_1_abc123")]
    [InlineData("EMAIL_1_abc123")]
    [InlineData("[EMAIL_01_abc123]")]
    [InlineData("[EMAIL_2_abc123]")]
    [InlineData("[EMAIL_1_ABC123]")]
    [InlineData("[EMAIL_1_abc12]")]
    [InlineData("[EMAIL_1_xyz789]")]
    [InlineData("[EMAIL_1]")]
    public void MangledOrForeignPlaceholder_NotRestored(string mangled)
    {
        var session = Pii();
        Assert.Equal("[EMAIL_1_abc123]", session.Redact("jan@acme.nl"));
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
        Assert.Equal("[EMAIL_1_abc123]", args["plain"]);
        Assert.Equal("""{"to":"[EMAIL_1_abc123]","cc":["[EMAIL_2_abc123]",3],"n":{"k":"x [EMAIL_1_abc123]"},"flag":true}""",
            ((JsonElement)args["body"]!).GetRawText());
    }

    [Fact]
    public void FunctionResult_JsonElementString_Redacted()
    {
        var session = Pii();
        var element = JsonDocument.Parse("\"reach jan@acme.nl\"").RootElement;
        var result = session.Redact([new ChatMessage(ChatRole.Tool, [new FunctionResultContent("c1", element)])]);
        var redacted = (JsonElement)((FunctionResultContent)result[0].Contents[0]).Result!;
        Assert.Equal("reach [EMAIL_1_abc123]", redacted.GetString());
        Assert.Equal("reach [EMAIL_1_abc123]", session.RedactResult("reach jan@acme.nl"));
        Assert.Equal(42, session.RedactResult(42));
        Assert.Null(session.RedactResult(null));
    }

    [Fact]
    public void Restore_FunctionCallArguments_RealValuesBack()
    {
        var session = Pii();
        session.Redact("jan@acme.nl");
        var call = new FunctionCallContent("c1", "send", new Dictionary<string, object?>(StringComparer.Ordinal) { ["to"] = "[EMAIL_1_abc123]", ["n"] = 5 });
        var restored = session.Restore([new ChatMessage(ChatRole.Assistant, [call, new TextContent("hi [EMAIL_1_abc123]")])]);
        var args = ((FunctionCallContent)restored[0].Contents[0]).Arguments!;
        Assert.Equal("jan@acme.nl", args["to"]);
        Assert.Equal(5, args["n"]);
        Assert.Equal("hi jan@acme.nl", ((TextContent)restored[0].Contents[1]).Text);

        var fnArgs = session.Restore(new AIFunctionArguments(StringComparer.Ordinal) { ["to"] = "[EMAIL_1_abc123]" }, StringComparer.Ordinal);
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
        Assert.Equal("[EMAIL_1_abc123]", ((TextContent)output[0].Contents[0]).Text);
    }

    [Fact]
    public void CountsByDetector_ReportsCountsOnly()
    {
        var session = new RedactionSession([new PiiLeakageDetector(), new CredentialExposureDetector()], Tag);
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
    public void CrossMessage_LiteralsStayLiteral_InTextAndToolArguments()
    {
        var session = Pii();
        var call = new FunctionCallContent("c", "f", new Dictionary<string, object?>(StringComparer.Ordinal) { ["a"] = "[EMAIL_1_old001]" });
        var result = session.Redact(
        [
            new ChatMessage(ChatRole.User, "mail jan@acme.nl"),
            new ChatMessage(ChatRole.User, "literal [EMAIL_1]"),
            new ChatMessage(ChatRole.Assistant, [call]),
        ]);
        Assert.Equal("mail [EMAIL_1_abc123]", result[0].Text);
        Assert.Equal("literal [EMAIL_1]", result[1].Text);
        Assert.Equal("[EMAIL_1_old001]", ((FunctionCallContent)result[2].Contents[0]).Arguments!["a"]);
        Assert.Equal("[EMAIL_1_old001]", session.Restore("[EMAIL_1_old001]"));
        Assert.Equal("mail jan@acme.nl", session.Restore(result[0].Text));
    }


    [Fact]
    public void RedactResult_AIContent_IsRedacted()
    {
        var session = Pii();
        var single = (TextContent)session.RedactResult(new TextContent("owner: jan@acme.nl"))!;
        Assert.Equal("owner: [EMAIL_1_abc123]", single.Text);

        var list = (IEnumerable<AIContent>)session.RedactResult(new List<AIContent> { new TextContent("a b@acme.nl") })!;
        Assert.Equal("a [EMAIL_2_abc123]", ((TextContent)Assert.Single(list)).Text);
    }

    [Fact]
    public void RedactResult_JsonNodeAndPocoAndCollections_AreRedactedAsJson()
    {
        var session = Pii();
        var node = (JsonElement)session.RedactResult(JsonNode.Parse("""{"m":"jan@acme.nl"}"""))!;
        Assert.Equal("""{"m":"[EMAIL_1_abc123]"}""", node.GetRawText());

        var poco = (JsonElement)session.RedactResult(new Owner { Name = "x", Emails = ["jan@acme.nl"] })!;
        Assert.Contains("[EMAIL_1_abc123]", poco.GetRawText(), StringComparison.Ordinal);
        Assert.DoesNotContain("acme", poco.GetRawText(), StringComparison.Ordinal);

        var dict = (JsonElement)session.RedactResult(new Dictionary<string, string>(StringComparer.Ordinal) { ["k"] = "jan@acme.nl" })!;
        Assert.Equal("""{"k":"[EMAIL_1_abc123]"}""", dict.GetRawText());

        var array = (List<object?>)session.RedactResult(new List<string> { "jan@acme.nl", "z" })!;
        Assert.Equal("[EMAIL_1_abc123]", array[0]);
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
        var session = new RedactionSession([a, b], Tag);
        var redacted = session.Redact("aaaa bbbb cccc dddd");
        Assert.Equal("[EMAIL_1_abc123] [EMAIL_2_abc123] [TAX_ID_1_abc123] [X1_1_abc123]", redacted);
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
        Assert.Equal("""{"[EMAIL_1_abc123]":{"x":1}}""", element.GetRawText());

        var restored = session.Restore(new List<ChatMessage>(redacted));
        var back = (JsonElement)((FunctionCallContent)restored[0].Contents[0]).Arguments!["m"]!;
        Assert.Equal("""{"jan@acme.nl":{"x":1}}""", back.GetRawText());
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
        Assert.Equal("[EMAIL_1_abc123]", Assert.Single(rDict).Value);
        Assert.Equal("[EMAIL_1_abc123]", Assert.Single(rDict).Key);
        Assert.Equal("""{"k":"[EMAIL_1_abc123]"}""", ((JsonElement)rArgs["n"]!).GetRawText());

        // The model echoes the arguments back as CLR containers and JsonNode.
        var echoed = new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["d"] = new Dictionary<string, object?>(StringComparer.Ordinal) { ["[EMAIL_1_abc123]"] = "[EMAIL_1_abc123]" },
            ["l"] = new List<object?> { "[EMAIL_1_abc123]", 7 },
            ["a"] = new object?[] { "[EMAIL_1_abc123]" },
            ["n"] = JsonNode.Parse("""{"k":"[EMAIL_1_abc123]"}"""),
            ["p"] = new Owner { Name = "[EMAIL_1_abc123]" },
        };
        var restored = session.Restore([new ChatMessage(ChatRole.Assistant, [new FunctionCallContent("c", "f", echoed)])]);
        var back = ((FunctionCallContent)restored[0].Contents[0]).Arguments!;
        var bDict = Assert.IsType<Dictionary<string, object?>>(back["d"]);
        Assert.Equal("jan@acme.nl", bDict["jan@acme.nl"]);
        Assert.Equal("jan@acme.nl", Assert.IsType<List<object?>>(back["l"])[0]);
        Assert.Equal("jan@acme.nl", Assert.IsType<object[]>(back["a"])[0]);
        Assert.Equal("jan@acme.nl", Assert.IsType<JsonNode>(back["n"], exactMatch: false)["k"]!.GetValue<string>());
        Assert.Equal("[EMAIL_1_abc123]", Assert.IsType<Owner>(back["p"]).Name);
    }

    [Fact]
    public void RestoreArguments_ReturnsCopy_InputAndBackingDictionaryUnchanged()
    {
        var session = Pii();
        session.Redact("jan@acme.nl");
        var services = new ServiceCollectionStub();
        var context = new Dictionary<object, object?> { ["k"] = "v" };
        var nested = new Dictionary<string, object?>(StringComparer.Ordinal) { ["x"] = "[EMAIL_1_abc123]" };
        var backing = new Dictionary<string, object?>(StringComparer.Ordinal) { ["to"] = "[EMAIL_1_abc123]", ["n"] = nested };
        var args = new AIFunctionArguments(backing, StringComparer.Ordinal) { Services = services, Context = context };

        var restored = session.Restore(args, StringComparer.Ordinal);

        Assert.NotSame(args, restored);
        Assert.Equal("jan@acme.nl", restored["to"]);
        Assert.Equal("jan@acme.nl", ((Dictionary<string, object?>)restored["n"]!)["x"]);
        Assert.Equal("[EMAIL_1_abc123]", args["to"]);
        Assert.Equal("[EMAIL_1_abc123]", backing["to"]);
        Assert.Equal("[EMAIL_1_abc123]", nested["x"]);
        Assert.Same(services, restored.Services);
        Assert.Same(context, restored.Context);
    }

    [Fact]
    public void RestoreArguments_OrdinalComparer_KeepsKeysDifferingOnlyInCase()
    {
        var session = Pii();
        session.Redact("jan@acme.nl");
        var args = new AIFunctionArguments(StringComparer.Ordinal) { ["id"] = "[EMAIL_1_abc123]", ["ID"] = "other" };
        var restored = session.Restore(args, StringComparer.Ordinal);
        Assert.Equal(2, restored.Count);
        Assert.Equal("jan@acme.nl", restored["id"]);
        Assert.Equal("other", restored["ID"]);
        Assert.False(restored.ContainsKey("Id"));
    }

    [Fact]
    public void RestoreArguments_CaseInsensitiveComparer_GivesCaseInsensitiveLookup()
    {
        var session = Pii();
        session.Redact("jan@acme.nl");
        var args = new AIFunctionArguments(StringComparer.OrdinalIgnoreCase) { ["To"] = "[EMAIL_1_abc123]" };
        var restored = session.Restore(args, StringComparer.OrdinalIgnoreCase);
        Assert.Equal("jan@acme.nl", restored["TO"]);
        Assert.Equal("[EMAIL_1_abc123]", args["to"]);
    }

    [Fact]
    public void RestoreArguments_ComparerThatMergesKeys_ThrowsWithoutValues()
    {
        var session = Pii();
        session.Redact("jan@acme.nl");
        var args = new AIFunctionArguments(StringComparer.Ordinal) { ["id"] = "[EMAIL_1_abc123]", ["ID"] = "[EMAIL_1_abc123]" };
        var ex = Assert.Throws<InvalidOperationException>(() => session.Restore(args, StringComparer.OrdinalIgnoreCase));
        Assert.DoesNotContain("jan@acme.nl", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void RestoreArguments_NullComparer_Throws()
    {
        var session = Pii();
        Assert.Throws<ArgumentNullException>(() => session.Restore(new AIFunctionArguments(StringComparer.Ordinal), null!));
    }

    [Fact]
    public void Redact_FunctionCallArguments_KeepSourceComparer()
    {
        var session = Pii();
        var insensitive = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
        {
            ["To"] = "jan@acme.nl",
            ["n"] = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase) { ["Inner"] = "jan@acme.nl" },
        };
        var ordinal = new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["id"] = "jan@acme.nl",
            ["ID"] = "other",
            ["n"] = new Dictionary<string, object?>(StringComparer.Ordinal) { ["x"] = "a", ["X"] = "b" },
        };
        var output = session.Redact([new ChatMessage(ChatRole.User,
            [new FunctionCallContent("c1", "f", insensitive), new FunctionCallContent("c2", "g", ordinal)])]);

        var first = ((FunctionCallContent)output[0].Contents[0]).Arguments!;
        Assert.Equal("[EMAIL_1_abc123]", first["TO"]);
        Assert.Equal("[EMAIL_1_abc123]", ((Dictionary<string, object?>)first["N"]!)["inner"]);

        var second = ((FunctionCallContent)output[0].Contents[1]).Arguments!;
        Assert.Equal(3, second.Count);
        Assert.Equal("[EMAIL_1_abc123]", second["id"]);
        Assert.Equal("other", second["ID"]);
        var nested = (Dictionary<string, object?>)second["n"]!;
        Assert.Equal(2, nested.Count);
        Assert.Same(StringComparer.Ordinal, nested.Comparer);
    }

    // A tool in this call can echo a placeholder it was given, such as a secret's. That token is this call's own:
    // it is not redacted again and restores to its value for the caller, never to a fresh token.
    [Fact]
    public void ResultEchoingAMintedToken_KeepsIt_AndItRestoresToItsValue()
    {
        var session = Pii();
        Assert.Equal("[EMAIL_1_abc123]", session.Redact("jan@acme.nl"));
        var later = (string)session.RedactResult("template [EMAIL_1_abc123]")!;
        Assert.Equal("template [EMAIL_1_abc123]", later);
        Assert.Equal("template jan@acme.nl", session.Restore(later));
        Assert.Equal(1, session.CountsByDetector["SEC-23"]["EMAIL"]);
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
        Assert.Equal("[EMAIL_1_abc123]", new string(chars));
    }

    [Fact]
    public void DataContent_HonoursCharset_AndUnknownCharsetFailsClosed()
    {
        var session = Pii();
        var utf16 = new DataContent(Encoding.Unicode.GetBytes("mail jan@acme.nl"), "text/plain; charset=utf-16");
        var result = session.Redact([new ChatMessage(ChatRole.User, [utf16])]);
        Assert.Equal("mail [EMAIL_1_abc123]", Encoding.Unicode.GetString(((DataContent)result[0].Contents[0]).Data.Span));

        var bogus = new DataContent(Encoding.UTF8.GetBytes("jan@acme.nl"), "text/plain; charset=bogus-xyz");
        var ex = Assert.Throws<InvalidOperationException>(() => session.Redact([new ChatMessage(ChatRole.User, [bogus])]));
        Assert.DoesNotContain("acme", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Restore_JsonElementArguments_RealValuesBack()
    {
        var session = Pii();
        session.Redact("jan@acme.nl");
        var json = JsonDocument.Parse("""{"to":["[EMAIL_1_abc123]"],"n":1}""").RootElement;
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
        Assert.Equal("think [EMAIL_1_abc123]", ((TextReasoningContent)result[0].Contents[0]).Text);
        Assert.Equal("mail [EMAIL_1_abc123]", Encoding.UTF8.GetString(((DataContent)result[0].Contents[1]).Data.Span));
        Assert.Equal(bytes, ((DataContent)result[0].Contents[2]).Data.ToArray());
    }

    [Fact]
    public void OutOfRangeSpan_Throws_WithoutValueInMessage()
    {
        var session = new RedactionSession([new FakeRedactor("TST-01", new RedactionSpan(5, 99, "X"))], Tag);
        var ex = Assert.Throws<InvalidOperationException>(() => session.Redact("secret-value"));
        Assert.DoesNotContain("secret", ex.Message, StringComparison.Ordinal);
        Assert.Contains("TST-01", ex.Message, StringComparison.Ordinal);
    }

    private sealed class SecretRedactor(params RedactionSpan[] spans) : IRedactingDetector
    {
        public DetectorId Id { get; } = new("TST-SECRET");
        public DetectorCategory Category => DetectorCategory.Security;
        public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct) =>
            ValueTask.FromResult(DetectionResult.Clean(Id));
        public IReadOnlyList<RedactionSpan> FindSpans(string text) => spans;
        public bool RestoreIntoToolArguments => false;
    }

    [Fact]
    public void Secret_RestoredInText_ButNeverIntoToolArguments_PiiIsRestoredIntoBoth()
    {
        var session = new RedactionSession([new PiiLeakageDetector(), new CredentialExposureDetector()], Tag);
        var redacted = session.Redact("jan@acme.nl api_key=abc123def456");
        Assert.Equal("[EMAIL_1_abc123] api_key=[API_KEY_1_abc123]", redacted);

        Assert.Equal("jan@acme.nl api_key=abc123def456", session.Restore(redacted));

        var args = session.Restore(
            new AIFunctionArguments(StringComparer.Ordinal) { ["to"] = "[EMAIL_1_abc123]", ["key"] = "[API_KEY_1_abc123]" }, StringComparer.Ordinal);
        Assert.Equal("jan@acme.nl", args["to"]);
        Assert.Equal("[API_KEY_1_abc123]", args["key"]);

        var reply = session.Restore(new List<ChatMessage>
        {
            new(ChatRole.Assistant, [
                new TextContent("[EMAIL_1_abc123] [API_KEY_1_abc123]"),
                new FunctionCallContent("c1", "Send", new Dictionary<string, object?>(StringComparer.Ordinal) { ["to"] = "[EMAIL_1_abc123]", ["key"] = "[API_KEY_1_abc123]" }),
            ]),
        });
        Assert.Equal("jan@acme.nl abc123def456", reply[0].Text);
        var call = Assert.IsType<FunctionCallContent>(reply[0].Contents[1]);
        Assert.Equal("jan@acme.nl", call.Arguments!["to"]);
        Assert.Equal("[API_KEY_1_abc123]", call.Arguments["key"]);
    }

    [Fact]
    public void MergedSpan_WithASecretDetector_IsNotRestoredIntoToolArguments()
    {
        var session = new RedactionSession(
        [
            new FakeRedactor("TST-01", new RedactionSpan(0, 6, "PHONE")),
            new SecretRedactor(new RedactionSpan(3, 6, "API_KEY")),
        ], Tag);
        var redacted = session.Redact("abcdefghij");
        Assert.Equal("[PHONE_1_abc123]j", redacted);

        var args = session.Restore(new AIFunctionArguments(StringComparer.Ordinal) { ["v"] = "[PHONE_1_abc123]" }, StringComparer.Ordinal);
        Assert.Equal("[PHONE_1_abc123]", args["v"]);
        Assert.Equal("abcdefghij", session.Restore(redacted));
    }

    [Fact]
    public void SameValue_FoundLaterByASecretDetector_LosesToolRestore()
    {
        var pii = new FakeRedactor("TST-01", new RedactionSpan(0, 5, "X"));
        var secret = new SecretRedactor(new RedactionSpan(0, 5, "X"));
        var first = new RedactionSession([pii], Tag);
        Assert.Equal("[X_1_abc123]", first.Redact("hello"));
        Assert.Equal("hello", first.Restore(new AIFunctionArguments(StringComparer.Ordinal) { ["v"] = "[X_1_abc123]" }, StringComparer.Ordinal)["v"]);

        var both = new RedactionSession([pii, secret], Tag);
        Assert.Equal("[X_1_abc123]", both.Redact("hello"));
        Assert.Equal("[X_1_abc123]", both.Restore(new AIFunctionArguments(StringComparer.Ordinal) { ["v"] = "[X_1_abc123]" }, StringComparer.Ordinal)["v"]);
    }


    [Fact]
    public void Restore_CallIsAnsweredOnlyByAResultThatFollowsIt()
    {
        var session = new RedactionSession([new CredentialExposureDetector()], Tag);
        Assert.Equal("api_key=[API_KEY_1_abc123]", session.Redact("api_key=abc123def456"));
        static FunctionCallContent Call(string id) =>
            new(id, "Lookup", new Dictionary<string, object?>(StringComparer.Ordinal) { ["key"] = "[API_KEY_1_abc123]" });

        var restored = session.Restore(new List<ChatMessage>
        {
            new(ChatRole.Assistant, [Call("call_0")]),
            new(ChatRole.Tool, [new FunctionResultContent("call_0", "ok")]),
            new(ChatRole.Assistant, [Call("call_0")]),
            new(ChatRole.Assistant, [Call("")]),
            new(ChatRole.Tool, [new FunctionResultContent("", "ok")]),
        });

        Assert.Equal("abc123def456", ((FunctionCallContent)restored[0].Contents[0]).Arguments!["key"]);
        Assert.Equal("[API_KEY_1_abc123]", ((FunctionCallContent)restored[2].Contents[0]).Arguments!["key"]);
        Assert.Equal("[API_KEY_1_abc123]", ((FunctionCallContent)restored[3].Contents[0]).Arguments!["key"]);
    }

    [Fact]
    public void Restore_ResultBeforeTheCall_DoesNotAnswerIt()
    {
        var session = new RedactionSession([new CredentialExposureDetector()], Tag);
        session.Redact("api_key=abc123def456");

        var restored = session.Restore(new List<ChatMessage>
        {
            new(ChatRole.Tool, [new FunctionResultContent("c1", "ok")]),
            new(ChatRole.Assistant, [new FunctionCallContent("c1", "Lookup", new Dictionary<string, object?>(StringComparer.Ordinal) { ["key"] = "[API_KEY_1_abc123]" })]),
        });

        Assert.Equal("[API_KEY_1_abc123]", ((FunctionCallContent)restored[1].Contents[0]).Arguments!["key"]);
    }

    [Fact]
    public void RedactRequest_CollectsEveryPlaceholderShapedToken_FromTextArgumentsAndResults()
    {
        var session = Pii();
        var request = session.RedactRequest(
        [
            new ChatMessage(ChatRole.User, "see jan@acme.nl and [email_2_abc123] and [IBAN_3]"),
            new ChatMessage(ChatRole.Assistant, [new FunctionCallContent("c", "f", new Dictionary<string, object?>(StringComparer.Ordinal) { ["k"] = "[API_KEY_1_old001]" })]),
            new ChatMessage(ChatRole.Tool, [new FunctionResultContent("c", "[IBAN_3_old001]")]),
        ]);

        Assert.Equal(
            new HashSet<string>(StringComparer.Ordinal) { "[EMAIL_1_abc123]", "[API_KEY_1_old001]", "[IBAN_3_old001]" },
            request.Placeholders);
    }


    // --- Final review fixes ---

    // A tool result that is a lazy sequence is converted once: enumerating it twice would cost twice and, for a
    // sequence that changes, redact a different serialization than the one that reaches the model.
    [Fact]
    public void RedactResult_LazySequence_IsEnumeratedOnce()
    {
        var session = Pii();
        var enumerations = 0;
        IEnumerable<string> Lazy()
        {
            enumerations++;
            yield return "jan@acme.nl";
            yield return "x";
        }

        var result = (JsonElement)session.RedactResult(Lazy())!;

        Assert.Equal(1, enumerations);
        Assert.Equal("""["[EMAIL_1]","x"]""", Placeholders.Untag(result.GetRawText()));
    }

    [Fact]
    public void RedactResult_LazyContents_AreEnumeratedOnce()
    {
        var session = Pii();
        var enumerations = 0;
        IEnumerable<AIContent> Lazy()
        {
            enumerations++;
            yield return new TextContent("a jan@acme.nl");
        }

        var result = (IEnumerable<AIContent>)session.RedactResult(Lazy())!;

        Assert.Equal(1, enumerations);
        Assert.Equal("a [EMAIL_1]", Placeholders.Untag(((TextContent)Assert.Single(result)).Text));
    }

    private static RedactionSpan[] EverySegment(int count, string type)
    {
        var spans = new RedactionSpan[count];
        for (var i = 0; i < count; i++)
        {
            spans[i] = new RedactionSpan(i * 5, 4, type);
        }
        return spans;
    }

    // Two detectors reporting the same start and length: the earlier detector in the list types the
    // placeholder and gets the count, every time. Enough spans that the sort is not an insertion sort.
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void SameSpanFromTwoDetectors_TheEarlierDetectorWins(bool reversed)
    {
        const int count = 40;
        var alpha = new FakeRedactor("TST-01", EverySegment(count, "ALPHA"));
        var beta = new FakeRedactor("TST-02", EverySegment(count, "BETA"));
        var text = new StringBuilder();
        for (var i = 0; i < count; i++)
        {
            text.Append(CultureInfo.InvariantCulture, $"v{i:D3} ");
        }

        var session = new RedactionSession(reversed ? [beta, alpha] : [alpha, beta]);
        var redacted = Placeholders.Untag(session.Redact(text.ToString()));

        var (winner, loser, winnerId) = reversed ? ("BETA", "ALPHA", "TST-02") : ("ALPHA", "BETA", "TST-01");
        Assert.DoesNotContain(loser, redacted, StringComparison.Ordinal);
        Assert.Contains($"[{winner}_{count}]", redacted, StringComparison.Ordinal);
        var counts = session.CountsByDetector;
        Assert.Equal(winnerId, Assert.Single(counts).Key);
        Assert.Equal(count, counts[winnerId][winner]);
    }
}
