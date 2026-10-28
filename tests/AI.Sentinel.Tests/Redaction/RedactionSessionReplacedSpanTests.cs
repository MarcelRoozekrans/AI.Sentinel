using AI.Sentinel.Detection;
using AI.Sentinel.Detectors.Security;
using AI.Sentinel.Domain;
using AI.Sentinel.Redaction;
using Xunit;

namespace AI.Sentinel.Tests.Redaction;

public class RedactionSessionReplacedSpanTests
{
    private sealed class FixedSpanRedactor(string id, int start, int length, string entityType) : IRedactingDetector
    {
        public DetectorId Id { get; } = new(id);
        public DetectorCategory Category => DetectorCategory.Security;
        public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct) =>
            ValueTask.FromResult(DetectionResult.Clean(Id));
        public IReadOnlyList<RedactionSpan> FindSpans(string text) => [new RedactionSpan(start, length, entityType)];
    }

    [Fact]
    public void Redact_ReportsReplacedSpans_InInputOffsets()
    {
        var session = new RedactionSession([new PiiLeakageDetector()]);
        var replaced = new List<ReplacedSpan>();
        const string input = "mail jan@example.com or call 0612345678";
        var output = session.Redact(input, replaced);

        Assert.Equal(2, replaced.Count);
        Assert.Equal("jan@example.com", input.Substring(replaced[0].Start, replaced[0].Length));
        Assert.Equal(("SEC-23", "EMAIL", Severity.Medium), (replaced[0].DetectorId, replaced[0].EntityType, replaced[0].Severity));
        Assert.Equal("0612345678", input.Substring(replaced[1].Start, replaced[1].Length));
        Assert.Contains(replaced[0].Token, output);
        Assert.Contains(replaced[1].Token, output);
    }

    [Fact]
    public void Redact_OverlappingSpansFromTwoDetectors_ReportOneMergedSpan()
    {
        // A reports [5,10) as SHORT, B reports [7,15) as LONGER (length 8 > 5).
        var replaced = new List<ReplacedSpan>();
        new RedactionSession([new FixedSpanRedactor("TST-A", 5, 5, "SHORT"), new FixedSpanRedactor("TST-B", 7, 8, "LONGER")])
            .Redact("0123456789abcdefghij", replaced);

        var span = Assert.Single(replaced);
        Assert.Equal((5, 10, "TST-B", "LONGER"), (span.Start, span.Length, span.DetectorId, span.EntityType));
    }

    [Fact]
    public void Redact_RepeatedValue_ReportsEachOccurrenceWithTheSameToken()
    {
        var replaced = new List<ReplacedSpan>();
        new RedactionSession([new PiiLeakageDetector()]).Redact("0612345678 en 0612345678", replaced);
        Assert.Equal(2, replaced.Count);
        Assert.Equal(replaced[0].Token, replaced[1].Token);
    }

    [Fact]
    public void Redact_SpanOverAPlaceholderTheSessionMinted_IsNotReported()
    {
        var session = new RedactionSession([new WholeTextRedactor()]);
        var first = new List<ReplacedSpan>();
        var token = session.Redact("0612345678", first);
        Assert.Single(first);

        // The redactor now reports the whole minted placeholder; the session leaves it alone and lists nothing.
        var second = new List<ReplacedSpan>();
        Assert.Equal(token, session.Redact(token, second));
        Assert.Empty(second);
    }

    private sealed class WholeTextRedactor : IRedactingDetector
    {
        public DetectorId Id { get; } = new("TST-W");
        public DetectorCategory Category => DetectorCategory.Security;
        public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct) =>
            ValueTask.FromResult(DetectionResult.Clean(Id));
        public IReadOnlyList<RedactionSpan> FindSpans(string text) => [new RedactionSpan(0, text.Length, "PHONE")];
    }

    [Fact]
    public void ReplacedSpan_ToString_PrintsTokenOnly()
        => Assert.Equal("[PHONE_1_abcdef]", new ReplacedSpan(0, 10, "SEC-23", "PHONE", null, "[PHONE_1_abcdef]").ToString());
}
