using Xunit;
using Microsoft.Extensions.AI;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using AI.Sentinel.Audit;
using AI.Sentinel.Detectors.Security;

namespace AI.Sentinel.Tests.Detectors.Security;

public class PiiLeakageDetectorTests
{
    private static SentinelContext Ctx(string text) => new(
        new AgentId("a"), new AgentId("b"), SessionId.New(),
        new List<ChatMessage> { new(ChatRole.User, text) },
        new List<AuditEntry>());

    [Fact]
    public async Task CleanText_ReturnsClean()
    {
        var d = new PiiLeakageDetector();
        var r = await d.AnalyzeAsync(Ctx("The weather is nice today."), default);
        Assert.Equal(Severity.None, r.Severity);
    }

    [Theory]
    [InlineData("My SSN is 123-45-6789")]
    [InlineData("SSN: 999-88-7777")]
    public async Task Ssn_Detected(string text)
    {
        var d = new PiiLeakageDetector();
        var r = await d.AnalyzeAsync(Ctx(text), default);
        Assert.Equal(Severity.High, r.Severity);
        Assert.Contains("SSN", r.Reason, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("Card: 4111 1111 1111 1111")]
    [InlineData("4111-1111-1111-1111")]
    [InlineData("4111111111111111")]
    public async Task CreditCard_Detected(string text)
    {
        var d = new PiiLeakageDetector();
        var r = await d.AnalyzeAsync(Ctx(text), default);
        Assert.Equal(Severity.Critical, r.Severity);
        Assert.Contains("Credit card", r.Reason, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("NL91ABNA0417164300")]
    [InlineData("DE89370400440532013000")]
    [InlineData("GB29NWBK60161331926819")]
    public async Task Iban_Detected(string text)
    {
        var d = new PiiLeakageDetector();
        var r = await d.AnalyzeAsync(Ctx(text), default);
        Assert.Equal(Severity.High, r.Severity);
        Assert.Contains("IBAN", r.Reason, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("BSN: 123456782")]
    [InlineData("burgerservicenummer 123456782")]
    public async Task Bsn_WithContext_Detected(string text)
    {
        var d = new PiiLeakageDetector();
        var r = await d.AnalyzeAsync(Ctx(text), default);
        Assert.Equal(Severity.High, r.Severity);
        Assert.Contains("BSN", r.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task BareNineDigits_WithoutContext_Clean()
    {
        var d = new PiiLeakageDetector();
        var r = await d.AnalyzeAsync(Ctx("Order number 123456782"), default);
        Assert.Equal(Severity.None, r.Severity);
    }

    [Fact]
    public async Task UkNino_Detected()
    {
        var d = new PiiLeakageDetector();
        var r = await d.AnalyzeAsync(Ctx("NINO: AB123456C"), default);
        Assert.Equal(Severity.High, r.Severity);
        Assert.Contains("National Insurance", r.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task EmailWithName_Detected()
    {
        var d = new PiiLeakageDetector();
        var r = await d.AnalyzeAsync(Ctx("Contact John Smith at john.smith@example.com"), default);
        Assert.Equal(Severity.Medium, r.Severity);
        Assert.Contains("Email", r.Reason, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("Call +31 6 12345678")]
    [InlineData("Phone: 555-867-5309")]
    [InlineData("+1-800-555-0199")]
    public async Task Phone_Detected(string text)
    {
        var d = new PiiLeakageDetector();
        var r = await d.AnalyzeAsync(Ctx(text), default);
        Assert.Equal(Severity.Medium, r.Severity);
        Assert.Contains("Phone", r.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Dob_Detected()
    {
        var d = new PiiLeakageDetector();
        var r = await d.AnalyzeAsync(Ctx("DOB: 15/03/1990"), default);
        Assert.Equal(Severity.Medium, r.Severity);
        Assert.Contains("Date of birth", r.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Passport_WithContext_Detected()
    {
        var d = new PiiLeakageDetector();
        var r = await d.AnalyzeAsync(Ctx("passport: AB1234567"), default);
        Assert.Equal(Severity.High, r.Severity);
        Assert.Contains("Passport", r.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task DeTaxId_WithContext_Detected()
    {
        var d = new PiiLeakageDetector();
        var r = await d.AnalyzeAsync(Ctx("Steuer-ID: 12 345 67890"), default);
        Assert.Equal(Severity.High, r.Severity);
        Assert.Contains("tax ID", r.Reason, StringComparison.Ordinal);
    }
}
