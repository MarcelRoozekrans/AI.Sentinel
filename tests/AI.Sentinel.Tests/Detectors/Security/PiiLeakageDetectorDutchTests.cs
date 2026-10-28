using Xunit;
using Microsoft.Extensions.AI;
using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using AI.Sentinel.Detectors.Security;

namespace AI.Sentinel.Tests.Detectors.Security;

public class PiiLeakageDetectorDutchTests
{
    private static SentinelContext Ctx(string text) => new(
        new AgentId("a"), new AgentId("b"), SessionId.New(),
        new List<ChatMessage> { new(ChatRole.User, text) },
        new List<AuditEntry>());

    private static async Task<DetectionResult> Analyze(string text) =>
        await new PiiLeakageDetector().AnalyzeAsync(Ctx(text), TestContext.Current.CancellationToken);

    [Theory]
    [InlineData("Bel hem op 0612345678", "0612345678")]
    [InlineData("tel:0201234567", "0201234567")]
    [InlineData("Telefoon (0612345678) graag terugbellen", "0612345678")]
    public async Task Phone_DutchWithoutSeparator_Detected(string text, string value)
    {
        var r = await Analyze(text);
        Assert.Equal(Severity.Medium, r.Severity);
        Assert.Contains("Phone", r.Reason, StringComparison.Ordinal);

        var span = Assert.Single(new PiiLeakageDetector().FindSpans(text));
        Assert.Equal(new RedactionSpan(text.IndexOf(value, StringComparison.Ordinal), value.Length, "PHONE") { Severity = Severity.Medium }, span);
    }

    // Digit runs of another length, or that are part of a larger token, are not a Dutch phone number.
    [Theory]
    [InlineData("Dossier 012345678 is gesloten.")]
    [InlineData("Referentie 06123456789 is verlopen.")]
    [InlineData("Code 0012345678 is ongeldig.")]
    [InlineData("Kenmerk AB0612345678 staat in het systeem.")]
    [InlineData("Meldingnummer 2024123456 is aangemaakt.")]
    public async Task Phone_OtherDigitRuns_StayClean(string text)
    {
        var r = await Analyze(text);
        Assert.Equal(Severity.None, r.Severity);
    }

    [Fact]
    public void Iban_WithTenDigitTail_YieldsOnlyIbanSpan()
    {
        var span = Assert.Single(new PiiLeakageDetector().FindSpans("NL91ABNA0417164300"));
        Assert.Equal("IBAN", span.EntityType);
    }

    [Theory]
    [InlineData("Bewoner is geboren op 12-03-1985.", "12-03-1985")]
    [InlineData("geboren 12/03/1985", "12/03/1985")]
    [InlineData("Geboortedatum: 12-03-1985", "12-03-1985")]
    [InlineData("geboorte datum 1-3-85", "1-3-85")]
    [InlineData("{\"geboorte_datum\": \"12-03-1985\"}", "12-03-1985")]
    [InlineData("{\"geboorteDatum\": \"12-03-1985\"}", "12-03-1985")]
    [InlineData("geb. 12.03.1985", "12.03.1985")]
    [InlineData("geb.datum: 12-03-1985", "12-03-1985")]
    [InlineData("Born on 12/03/1985", "12/03/1985")]
    [InlineData("geboren op 12 maart 1985", "12 maart 1985")]
    [InlineData("Geboren: 3 mrt. 1985", "3 mrt. 1985")]
    [InlineData("geboortedatum 1 okt 1990", "1 okt 1990")]
    [InlineData("born 12 March 1985", "12 March 1985")]
    [InlineData("DOB: March 12, 1985", "March 12, 1985")]
    [InlineData("born on Oct. 3 1990", "Oct. 3 1990")]
    [InlineData("date of birth: 7 september 2001", "7 september 2001")]
    public async Task Dob_DutchKeywordsAndWrittenMonths_Detected(string text, string value)
    {
        var r = await Analyze(text);
        Assert.Equal(Severity.Medium, r.Severity);
        Assert.Contains("Date of birth", r.Reason, StringComparison.Ordinal);

        var span = Assert.Single(new PiiLeakageDetector().FindSpans(text));
        Assert.Equal(new RedactionSpan(text.IndexOf(value, StringComparison.Ordinal), value.Length, "DATE_OF_BIRTH") { Severity = Severity.Medium }, span);
    }

    [Theory]
    [InlineData("Bewoner is geboren in Syrië.")]
    [InlineData("Ze is geboren in maart.")]
    [InlineData("geboren op 12 maart")]
    [InlineData("Het incident was op 12 maart 1985 al eens gemeld.")]
    [InlineData("Geboren op een boerderij, sinds 2019 op de locatie.")]
    public async Task Dob_WithoutKeywordOrDate_StaysClean(string text)
    {
        var r = await Analyze(text);
        Assert.Equal(Severity.None, r.Severity);
    }
}
