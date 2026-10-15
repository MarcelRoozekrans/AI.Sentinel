using Xunit;
using Microsoft.Extensions.AI;
using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using AI.Sentinel.Detectors.Security;
using AI.Sentinel.Domain;

namespace AI.Sentinel.Tests.Detectors.Security;

public class PiiLeakageDetectorSpanTests
{
    [Fact]
    public void FindSpans_BareEmail_ReturnsEmailSpan()
    {
        var spans = new PiiLeakageDetector().FindSpans("mail jan@acme.nl now");
        var span = Assert.Single(spans);
        Assert.Equal(new RedactionSpan(5, 11, "EMAIL"), span);
    }

    [Fact]
    public void FindSpans_TwoIbansAndAPhone_ReturnsAllThree()
    {
        const string text = "from NL91ABNA0417164300 to DE89BANK3704004405 or call +1-800-555-0199";
        var spans = new PiiLeakageDetector().FindSpans(text);
        Assert.Equal(3, spans.Count);
        Assert.Contains(new RedactionSpan(text.IndexOf("NL91", StringComparison.Ordinal), 18, "IBAN"), spans);
        Assert.Contains(new RedactionSpan(text.IndexOf("DE89", StringComparison.Ordinal), 18, "IBAN"), spans);
        Assert.Contains(new RedactionSpan(text.IndexOf("+1-800", StringComparison.Ordinal), 15, "PHONE"), spans);
    }

    [Theory]
    [InlineData("BSN: 123456789", "123456789", "BSN")]
    [InlineData("passport: AB123456", "AB123456", "PASSPORT")]
    [InlineData("Steuer-ID: 12 345 67890", "12 345 67890", "TAX_ID")]
    [InlineData("born 01/02/1990", "01/02/1990", "DATE_OF_BIRTH")]
    public void FindSpans_KeywordPrefixedTypes_SpanCoversValueOnly(string text, string value, string entity)
    {
        var spans = new PiiLeakageDetector().FindSpans(text);
        var span = Assert.Single(spans);
        Assert.Equal(new RedactionSpan(text.IndexOf(value, StringComparison.Ordinal), value.Length, entity), span);
    }

    [Theory]
    [InlineData("4111 1111 1111 1111", "CREDIT_CARD")]
    [InlineData("123-45-6789", "SSN")]
    [InlineData("AB123456C", "NINO")]
    public void FindSpans_PlainTypes_SpanCoversMatch(string value, string entity)
    {
        var text = "x " + value + " y";
        var span = Assert.Single(new PiiLeakageDetector().FindSpans(text));
        Assert.Equal(new RedactionSpan(2, value.Length, entity), span);
    }

    [Fact]
    public void FindSpans_CleanText_ReturnsEmpty()
        => Assert.Empty(new PiiLeakageDetector().FindSpans("The weather is nice today."));

    [Fact]
    public async Task AnalyzeAsync_BareEmail_IsMedium()
    {
        var ctx = new SentinelContext(
            new AgentId("a"), new AgentId("b"), SessionId.New(),
            new List<ChatMessage> { new(ChatRole.User, "mail jan@acme.nl now") },
            new List<AuditEntry>());
        var r = await new PiiLeakageDetector().AnalyzeAsync(ctx, TestContext.Current.CancellationToken);
        Assert.Equal(Severity.Medium, r.Severity);
        Assert.Equal("Email address detected", r.Reason);
    }
}
