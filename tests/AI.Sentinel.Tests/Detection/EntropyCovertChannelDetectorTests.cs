using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using AI.Sentinel.Detectors.Security;
using AI.Sentinel.Domain;
using Microsoft.Extensions.AI;
using Xunit;

namespace AI.Sentinel.Tests.Detection;

/// <summary>#213. SEC-08 was a StubDetector that always returned Clean, and because the escalation
/// gate requires Severity >= Medium it could never fire even with an EscalationClient configured —
/// a control documented as available that no configuration could switch on. Entropy needs no
/// infrastructure the pipeline lacks, so it is now a real rule-based detector.
/// <para>
/// A covert channel looks like a long, structureless, high-entropy run: encoded or encrypted data
/// smuggled through text. The precision cases below matter more than the detection ones — hashes,
/// identifiers and URLs are long and random-looking too, and a detector that flags those is one
/// that gets turned off.
/// </para></summary>
public class EntropyCovertChannelDetectorTests
{
    private static SentinelContext Context(string text) => new(
        new AgentId("a"), new AgentId("b"), SessionId.New(),
        new List<ChatMessage> { new(ChatRole.User, text) },
        new List<AuditEntry>());

    private static async Task<DetectionResult> AnalyzeAsync(string text) =>
        await new EntropyCovertChannelDetector().AnalyzeAsync(Context(text), TestContext.Current.CancellationToken);

    [Theory]
    // Base64 of random bytes — the shape a covert channel actually takes.
    [InlineData("Here is the payload: qX7vK2mZp9RtLw4JhB6NcF8sYdQe1AgU3TiO5WxV0zPrMkHn")]
    [InlineData("aGVsbG8gd29ybGQgdGhpcyBpcyBhIHZlcnkgbG9uZyBiYXNlNjQgc3RyaW5nIHdpdGggaGlnaCBlbnRyb3B5")]
    public async Task LongHighEntropyRun_IsFlagged(string text)
    {
        var result = await AnalyzeAsync(text);

        Assert.False(result.IsClean, "a long high-entropy run should be flagged");
        Assert.Equal(new DetectorId("SEC-08"), result.DetectorId);
    }

    /// <summary>Precision. Every one of these is long and random-looking, and none is a covert
    /// channel.</summary>
    [Theory]
    [InlineData("commit 9f8e7d6c5b4a39281706f5e4d3c2b1a098765432 fixes the parser")]           // 40-char git sha
    [InlineData("sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")]     // 64-char hex digest
    [InlineData("request id 123e4567-e89b-12d3-a456-426614174000 failed validation")]           // uuid
    [InlineData("see https://example.com/docs/v2/reference/detectors?category=security&page=3")] // long url
    [InlineData("the quick brown fox jumps over the lazy dog and keeps on running for a while")] // prose
    [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]            // long, zero entropy
    public async Task LongButStructuredOrLowEntropyText_IsNotFlagged(string text)
    {
        var result = await AnalyzeAsync(text);

        Assert.True(result.IsClean, $"false positive: {result.Reason}");
    }

    [Fact]
    public async Task ShortTokens_AreNotFlagged_HoweverRandom()
    {
        // Too short to carry a meaningful payload, and short random strings are everywhere.
        var result = await AnalyzeAsync("token qX7vK2mZp9RtLw4J done");

        Assert.True(result.IsClean, $"false positive: {result.Reason}");
    }

    [Fact]
    public async Task EmptyText_IsClean()
    {
        var result = await AnalyzeAsync(string.Empty);

        Assert.True(result.IsClean);
    }

    /// <summary>The finding must be re-classifiable: a long high-entropy run is suspicious, not
    /// conclusive, which is exactly what ILlmEscalatingDetector is for. Implementing it on a stub
    /// that always returned Clean was the bug; implementing it on a detector that produces findings
    /// is the intended use.</summary>
    [Fact]
    public void Detector_IsEscalatable()
    {
        Assert.IsAssignableFrom<ILlmEscalatingDetector>(new EntropyCovertChannelDetector());
    }

    [Fact]
    public async Task Reason_NamesTheEvidence_WithoutEchoingTheWholePayload()
    {
        var result = await AnalyzeAsync("data: qX7vK2mZp9RtLw4JhB6NcF8sYdQe1AgU3TiO5WxV0zPrMkHn");

        Assert.False(result.IsClean);
        Assert.Contains("entropy", result.Reason, StringComparison.OrdinalIgnoreCase);
        Assert.True(result.Reason.Length < 200, $"reason is unbounded: {result.Reason.Length} chars");
    }
}
