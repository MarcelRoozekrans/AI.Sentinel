using System.Text.Json;
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
}
