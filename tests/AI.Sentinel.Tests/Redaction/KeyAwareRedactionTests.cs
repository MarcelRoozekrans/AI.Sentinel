using System.Text.Json;
using AI.Sentinel.Detection;
using AI.Sentinel.Detectors.Security;
using AI.Sentinel.Redaction;
using Microsoft.Extensions.AI;
using Xunit;

namespace AI.Sentinel.Tests.Redaction;

/// <summary>
/// A JSON string value is redacted in the context of its key, as the scan sees it: <c>"password": "hunter2"</c>.
/// A value only a key makes sensitive is then redacted, rather than found by the scan and left to the fallback.
/// </summary>
public class KeyAwareRedactionTests
{
    private const string Tag = "abc123";

    private static RedactionSession Session() =>
        new([new PiiLeakageDetector(), new CredentialExposureDetector()], Tag);

    private static JsonElement Json(string json)
    {
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.Clone();
    }

    private static string RedactJson(RedactionSession session, string json) =>
        session.RedactJsonValues(Json(json)).GetRawText();

    [Fact]
    public void ValueRecognisedByItsKey_IsRedacted_KeyKept()
    {
        var session = Session();

        Assert.Equal("""{"password":"[PASSWORD_1_abc123]"}""", RedactJson(session, """{"password":"hunter2"}"""));
        Assert.Equal("hunter2", session.Restore("[PASSWORD_1_abc123]"));
        Assert.Equal(1, session.CountsByDetector["SEC-02"]["PASSWORD"]);
    }

    [Fact]
    public void NestedObjects_AreRedactedByTheirOwnKey()
    {
        var session = Session();

        Assert.Equal(
            """{"db":{"host":"db.local","password":"[PASSWORD_1_abc123]","auth":{"api_key":"[API_KEY_1_abc123]"}},"n":3}""",
            RedactJson(session, """{"db":{"host":"db.local","password":"hunter2","auth":{"api_key":"zebra-orchid"}},"n":3}"""));
    }

    // A span over part of the key and part of the value redacts the value part only.
    [Fact]
    public void SpanStartingInTheKey_RedactsTheValuePartOnly()
    {
        var session = Session();

        Assert.Equal(
            """{"Authorization":"Bearer [BEARER_TOKEN_1_abc123]"}""",
            RedactJson(session, """{"Authorization":"Bearer abc.def"}"""));
    }

    // The scan escapes " and \ in the rendered pair; the span is mapped back onto the value as it is.
    [Fact]
    public void EscapedCharacters_MapBackOntoTheValue()
    {
        var session = Session();

        Assert.Equal("""{"password":"[PASSWORD_1_abc123]"}""", RedactJson(session, """{"password":"hun\"ter\\2"}"""));
        Assert.Equal("hun\"ter\\2", session.Restore("[PASSWORD_1_abc123]"));
    }

    [Theory]
    [InlineData("""{"contact":"mail jan@acme.nl"}""", """{"contact":"mail [EMAIL_1_abc123]"}""")]
    [InlineData("""{"note":"api_key=abc123def456"}""", """{"note":"api_key=[API_KEY_1_abc123]"}""")]
    [InlineData("""{"api_key":"sk-abcdefghijklmnopqrstuvwxyz0123456789"}""", """{"api_key":"[API_KEY_1_abc123]"}""")]
    [InlineData("""{"password":"jan@acme.nl"}""", """{"password":"[EMAIL_1_abc123]"}""")]
    public void ValueMatchingOnItsOwn_IsRedactedAsBefore(string input, string expected)
    {
        Assert.Equal(expected, RedactJson(Session(), input));
    }

    // The key's span covers the whole value, more than the value's own span, and the two merge as overlapping spans
    // do. Redacting the value's span only would leave "password": "password: [PASSWORD_1_abc123]", which the scan
    // still flags, since the key's value is then not a placeholder.
    [Theory]
    [InlineData("""{"password":"password: hunter2"}""", """{"password":"[PASSWORD_1_abc123]"}""")]
    [InlineData("""{"password":"hunter2 jan@acme.nl"}""", """{"password":"[PASSWORD_1_abc123]"}""")]
    public void KeySpanCoveringMoreThanTheValueSpan_RedactsTheWholeValue(string input, string expected)
    {
        Assert.Equal(expected, RedactJson(Session(), input));
    }

    [Theory]
    [InlineData("""{"title":"hello world","count":"3","password_hint":"pet name"}""")]
    [InlineData("""{"items":["hunter2","x"]}""")]
    [InlineData("""["hunter2"]""")]
    [InlineData("\"hunter2\"")]
    public void NoSecretKey_OrNoKeyAtAll_IsUntouched(string input)
    {
        var session = Session();

        Assert.Equal(input, RedactJson(session, input));
        Assert.False(session.HasRedactions);
    }

    // The 3.0 in-process path: tool-call arguments on their way to the model, as plain strings and as JSON.
    [Fact]
    public void ToolCallArguments_RedactedByKey_SecretNeverRestoredIntoToolArguments()
    {
        var session = Session();
        var call = new FunctionCallContent("c1", "Lookup", new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["api_key"] = "zebra-orchid",
            ["body"] = Json("""{"password":"hunter2"}"""),
            ["password"] = Json("\"velvet-otter\""),
        });

        var redacted = session.RedactRequest([new ChatMessage(ChatRole.Assistant, [call])]);

        var args = Assert.IsType<FunctionCallContent>(redacted.Messages[0].Contents[0]).Arguments!;
        Assert.Equal("[API_KEY_1_abc123]", args["api_key"]);
        Assert.Equal("""{"password":"[PASSWORD_1_abc123]"}""", ((JsonElement)args["body"]!).GetRawText());
        Assert.Equal("[PASSWORD_2_abc123]", ((JsonElement)args["password"]!).GetString());
        Assert.Contains("[API_KEY_1_abc123]", redacted.Placeholders);

        var toolArgs = session.Restore(
            new AIFunctionArguments(StringComparer.Ordinal) { ["api_key"] = "[API_KEY_1_abc123]" }, StringComparer.Ordinal);
        Assert.Equal("[API_KEY_1_abc123]", toolArgs["api_key"]);
        Assert.Equal("zebra-orchid", session.Restore("[API_KEY_1_abc123]"));
    }

    [Fact]
    public void ToolResult_RedactedByKey()
    {
        var session = Session();

        var result = session.RedactResult(Json("""{"user":"jan","password":"hunter2"}"""));

        Assert.Equal("""{"user":"jan","password":"[PASSWORD_1_abc123]"}""", ((JsonElement)result!).GetRawText());
    }

    // Restoring never needs the key: the placeholder alone names the value.
    [Fact]
    public void RestoredJson_GetsTheValueBack()
    {
        var session = Session();
        var redacted = session.RedactResult(Json("""{"password":"hunter2"}"""));
        var call = new FunctionCallContent("c1", "f", new Dictionary<string, object?>(StringComparer.Ordinal) { ["m"] = redacted });

        var restored = session.Restore([new ChatMessage(ChatRole.Assistant, [call]), new ChatMessage(ChatRole.Tool, [new FunctionResultContent("c1", "ok")])]);

        var back = (JsonElement)((FunctionCallContent)restored[0].Contents[0]).Arguments!["m"]!;
        Assert.Equal("""{"password":"hunter2"}""", back.GetRawText());
    }

    // The span a detector reports for the rendered pair must lie inside that text, or nothing is redacted.
    [Fact]
    public void SpanOutsideTheRenderedPair_Throws()
    {
        var session = new RedactionSession([new OutOfRange()], Tag);

        Assert.Throws<InvalidOperationException>(() => session.RedactJsonValues(Json("""{"k":"v"}""")));
    }

    private sealed class OutOfRange : IRedactingDetector
    {
        public AI.Sentinel.Domain.DetectorId Id { get; } = new("TST-01");
        public DetectorCategory Category => DetectorCategory.Security;
        public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct) =>
            ValueTask.FromResult(DetectionResult.Clean(Id));
        public IReadOnlyList<RedactionSpan> FindSpans(string text) =>
            text.Length > 1 ? [new RedactionSpan(0, text.Length + 1, "X")] : [];
    }
}
