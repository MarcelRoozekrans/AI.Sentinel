using Xunit;
using Microsoft.Extensions.AI;
using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using AI.Sentinel.Detectors.Security;
using AI.Sentinel.Domain;

namespace AI.Sentinel.Tests.Detectors.Security;

public class PiiLeakageDetectorSpanTests
{
    private static SentinelContext Ctx(string text) => new(
        new AgentId("a"), new AgentId("b"), SessionId.New(),
        new List<ChatMessage> { new(ChatRole.User, text) }, new List<AuditEntry>());

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

    [Fact]
    public void FindSpans_TwoEmails_ReturnsBothSortedByStart()
    {
        const string text = "a@b.com and c.d@e.org";
        var spans = new PiiLeakageDetector().FindSpans(text);
        Assert.Equal(
            new[] { new RedactionSpan(0, 7, "EMAIL"), new RedactionSpan(12, 9, "EMAIL") },
            spans);
    }

    [Theory]
    [InlineData("lodash@4.17.21")]
    [InlineData("user@host")]
    public void FindSpans_NotAnEmail_ReturnsEmpty(string text)
        => Assert.Empty(new PiiLeakageDetector().FindSpans(text));

    [Theory]
    [InlineData("user@163.com")]
    [InlineData("jan@3m.com")]
    public void FindSpans_DomainStartingWithDigit_IsEmail(string text)
        => Assert.Equal(new RedactionSpan(0, text.Length, "EMAIL"), Assert.Single(new PiiLeakageDetector().FindSpans(text)));

    [Theory]
    [InlineData("a-")]
    [InlineData("a.")]
    [InlineData("a+")]
    public void FindSpans_LongInputWithoutAt_IsEmpty(string unit)
        => Assert.Empty(new PiiLeakageDetector().FindSpans(string.Concat(Enumerable.Repeat(unit, 50_000))));

    // JSON, as the scan renders it: a quote between the keyword and the colon, and around the value.
    [Theory]
    [InlineData("{\"BSN\": \"123456789\"}", "123456789", "BSN")]
    [InlineData("\"burgerservicenummer\": \"123456789\"", "123456789", "BSN")]
    [InlineData("{\"passport\": \"AB123456\"}", "AB123456", "PASSPORT")]
    [InlineData("{\"Steuer-ID\": \"12 345 67890\"}", "12 345 67890", "TAX_ID")]
    [InlineData("{\"tax id\": \"12345 67890\"}", "12345 67890", "TAX_ID")]
    [InlineData("{\"DOB\": \"01/02/1990\"}", "01/02/1990", "DATE_OF_BIRTH")]
    [InlineData("{'born': '01-02-1990'}", "01-02-1990", "DATE_OF_BIRTH")]
    public async Task FindSpans_KeywordPrefixedTypesInJson_SpanCoversValueOnly(string text, string value, string entity)
    {
        var detector = new PiiLeakageDetector();
        var span = Assert.Single(detector.FindSpans(text));
        Assert.Equal(new RedactionSpan(text.IndexOf(value, StringComparison.Ordinal), value.Length, entity), span);
        Assert.NotEqual(Severity.None, (await detector.AnalyzeAsync(Ctx(text), TestContext.Current.CancellationToken)).Severity);
    }

    // Multi-word keywords written as identifiers, as JSON keys usually are.
    [Theory]
    [InlineData("{\"date_of_birth\": \"01/02/1990\"}", "01/02/1990", "DATE_OF_BIRTH")]
    [InlineData("{\"date-of-birth\": \"01/02/1990\"}", "01/02/1990", "DATE_OF_BIRTH")]
    [InlineData("{\"dateOfBirth\": \"01/02/1990\"}", "01/02/1990", "DATE_OF_BIRTH")]
    [InlineData("{\"tax_id\": \"12345 67890\"}", "12345 67890", "TAX_ID")]
    [InlineData("{\"tax-id\": \"12345 67890\"}", "12345 67890", "TAX_ID")]
    [InlineData("{\"taxId\": \"12345 67890\"}", "12345 67890", "TAX_ID")]
    [InlineData("{\"steuer_id\": \"12 345 67890\"}", "12 345 67890", "TAX_ID")]
    [InlineData("{\"SteuerID\": \"12 345 67890\"}", "12 345 67890", "TAX_ID")]
    public void FindSpans_MultiWordKeywordAsIdentifier_SpanCoversValueOnly(string text, string value, string entity)
    {
        var span = Assert.Single(new PiiLeakageDetector().FindSpans(text));
        Assert.Equal(new RedactionSpan(text.IndexOf(value, StringComparison.Ordinal), value.Length, entity), span);
    }

    // The plain-text forms these patterns matched before still match the same value.
    [Theory]
    [InlineData("date of birth 01/02/1990", "01/02/1990", "DATE_OF_BIRTH")]
    [InlineData("Date  of\tbirth: 1-2-90", "1-2-90", "DATE_OF_BIRTH")]
    [InlineData("tax id 12 345 67890", "12 345 67890", "TAX_ID")]
    [InlineData("Tax  ID: 12345 67890", "12345 67890", "TAX_ID")]
    [InlineData("Steuer-ID 12 345 67890", "12 345 67890", "TAX_ID")]
    [InlineData("SteuerID=12 345 67890", "12 345 67890", "TAX_ID")]
    [InlineData("born 01/02/1990", "01/02/1990", "DATE_OF_BIRTH")]
    public void FindSpans_MultiWordKeywordPlainText_Unchanged(string text, string value, string entity)
    {
        var span = Assert.Single(new PiiLeakageDetector().FindSpans(text));
        Assert.Equal(new RedactionSpan(text.IndexOf(value, StringComparison.Ordinal), value.Length, entity), span);
    }

    [Theory]
    [InlineData("bsn: 123456789", "123456789", "BSN")]
    [InlineData("Passport: ab123456", "ab123456", "PASSPORT")]
    [InlineData("DOB: 01.02.1990", "01.02.1990", "DATE_OF_BIRTH")]
    [InlineData("TAX ID 12345 67890", "12345 67890", "TAX_ID")]
    public void FindSpans_KeywordCaseAndSeparatorVariants_SpanCoversValueOnly(string text, string value, string entity)
    {
        var span = Assert.Single(new PiiLeakageDetector().FindSpans(text));
        Assert.Equal(new RedactionSpan(text.IndexOf(value, StringComparison.Ordinal), value.Length, entity), span);
    }

    [Fact]
    public void FindSpans_EmailNextToName_SpansOnlyTheEmail()
    {
        const string text = "Contact John Smith at john.smith@example.com";
        var span = Assert.Single(new PiiLeakageDetector().FindSpans(text));
        Assert.Equal(new RedactionSpan(22, 22, "EMAIL"), span);
    }

    [Fact]
    public void Normalize_EqualRanges_KeepsTheEarlierHigherSeverityType()
    {
        var kept = RedactionSpanCollector.Normalize(new List<RedactionSpan>
        {
            new(0, 10, "SSN"),
            new(0, 10, "PHONE"),
            new(2, 3, "EMAIL"),
        });
        Assert.Equal(new[] { new RedactionSpan(0, 10, "SSN") }, kept);
    }

    [Fact]
    public void Normalize_DropsContainedSpans_KeepsPartialOverlaps_SortsByStartLongerFirst()
    {
        var kept = RedactionSpanCollector.Normalize(new List<RedactionSpan>
        {
            new(20, 5, "C"),
            new(3, 4, "B"),
            new(0, 10, "A"),
            new(8, 6, "D"),
            new(20, 5, "E"),
            new(21, 2, "F"),
            new(0, 12, "G"),
        });
        Assert.Equal(new[] { new RedactionSpan(0, 12, "G"), new RedactionSpan(8, 6, "D"), new RedactionSpan(20, 5, "C") }, kept);
    }
}
