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

    /// <summary>#470. Tool data a check of about 3,000 real file reads flagged: identifiers and paths are made of
    /// words, alphabet tables are ordered, and digests and inline images are encoded but not smuggled.</summary>
    [Theory]
    [InlineData("public void Migration_FromV1ToCurrent_AddsPolicyCodeColumnWithDefault()")]                     // test name
    [InlineData("ExpiryObservedByAProcessThatNeverSawTheRequest_InMemory_WritesTheRealRequestId")]              // test name
    [InlineData("throw FormatBCRYPT_KEY_LENGTHS_STRUCT_InvalidKeyLength();")]                                   // mixed constant
    [InlineData("export SENTINEL_APPROVAL_CONFIG=/etc/sentinel/approvals")]                                     // env assignment
    [InlineData("https://github.com/dotnet/runtime/blob/da9b16f2804e87c9c1ca9dcd9036e7b53e724f5d/src/libraries/System")] // blob url
    [InlineData("https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/SharedArrayBuffer")]  // docs url
    [InlineData("var lookup = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'")]           // alphabet table
    [InlineData("<div class=\"sidebar-navigation-collapsed-item-with-nested-dropdown-menu\">")]             // kebab case
    [InlineData("pkg integrity=sha512-7mJJl+wf1AByoT0PknQiQfOPnVNT4fevGrUBVWO4HXsnYn1aQPyRyrELYrNUFleUBM++KzMKN6QaxHPk0t/6/g==")] // unquoted digest
    [InlineData("dotnet add package microsoft-extensions-dependencyinjection-abstractions-v10")]              // package id
    [InlineData("\"integrity\": \"sha512-7mJJl+wf1AByoT0PknQiQfOPnVNT4fevGrUBVWO4HXsnYn1aQPyRyrELYrNUFleUBM++KzMKN6QaxHPk0t/6/g==\"")] // npm lock
    [InlineData("<script src=\"x.js\" integrity=\"sha384-HGfztofotfshcF7+8n44JQL2oJmowVChPTg48S+jvZoztPfvwD79OC/LTtG6dMp+\"></script>")] // SRI
    [InlineData("background: url(\"data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNTYiIGhlaWdodD0iNDkiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyIgeG1sbn\")")] // inline image
    [InlineData("<img src=\"data:image/png;base64,iVBORw0KGgq0LQ5B+fAF879b2GcEjMlrXWCU1wJzC7Uun/T0Mh7BPu3R8XZYg1rk\">")]   // png
    [InlineData("\"sha1-+yrfKkpQ9jKK4K2gNC7w97Ay9/c=\" \"sha256-5GJMBVxqKu8lQxBUTdGalgCYrbVWEE9a0U57slAve3g=\"")]   // sha1, sha256
    [InlineData("golang.org/x/text v0.14.0 h1:5GJMBVxqKu8lQxBUTdGalgCYrbVWEE9a0U57slAve3g=")]                    // go.sum
    public async Task ToolDataThatLooksEncodedButIsNot_IsNotFlagged(string text)
    {
        var result = await AnalyzeAsync(text);

        Assert.True(result.IsClean, $"false positive: {result.Reason}");
    }

    /// <summary>What the precision rules must not let through: base32 is one case, like a constant, but random; a
    /// data URI that is not an image or font is a payload; and a digest prefix covers only the run after it.</summary>
    [Theory]
    [InlineData("dns lookup KLZCMZNGBQJNFCIYLWKQ52EBGYERM33LCE6RPDLMB7JZAH7SHGQ2BFPSB6JZKZIM.example.com")]       // base32
    [InlineData("dns lookup klzcmzngbqjnfciylwkq52ebgyerm33lce6rpdlmb7jzah7shgq2bfpsb6jzkzim.example.com")]       // base32, lower
    [InlineData("fetch(\"data:text/plain;base64,+TgLjtsiSmskih6STo/Qri4alJKjMF8YjLYQkA+eNH+uiG3GUHeV7A==\")")]   // non-image data uri
    [InlineData("sha512-abc then qX7vK2mZp9RtLw4JhB6NcF8sYdQe1AgU3TiO5WxV0zPrMkHn")]                         // prefix elsewhere
    [InlineData("token=W0ZFnK-5kLKXMKJHwD0w8z-A-qfqMuCuCqAPAkVCbAafCRo4ikcSwQ")]                              // base64url, split by '-'
    [InlineData("n0G9W8uw8de9puyHB9d3xvE/pg3mKBxfeN4/YYsakj8DuzdoRy7q3sRjKMPMEiOennEgIQD43wE1xjf1=sha1-+yrfKkpQ9jKK4K2gNC7w97Ay9/c=")] // payload ahead of a digest
    [InlineData("url(\"data:image/png;base64,n0G9W8uw8de9puyHB9d3xvE/pg3mKBxfeN4/YYsakj8DuzdoRy7q3sRjKMPMEiOennEgIQD43wE1xjf1\")")] // not a png
    [InlineData("h1:n0G9W8uw8de9puyHB9d3xvE/pg3mKBxfeN4/YYsakj8DuzdoRy7q3sRjKMPMEiOennEgIQD43wE1xjf1")]        // too long for h1
    [InlineData("\"sha512-qX7vK2mZp9RtLw4JhB6NcF8sYdQe1AgU3TiO5WxV0zPrMkHnqX7vK2mZp9RtLw4JhB6NcF8sYdQe1AgU3TiO5WxV0zPrMkHnqX7vK2mZp9RtLw4JhB6N\"")] // too long for its digest
    public async Task EncodedPayloadNearThosePatterns_IsStillFlagged(string text)
    {
        var result = await AnalyzeAsync(text);

        Assert.False(result.IsClean, "an encoded payload should be flagged");
    }

    // A large lock file is examined up to a limit. A digest that the limit cuts through is still a whole digest.
    [Fact]
    public async Task DigestAcrossTheExaminedLimit_IsJudgedWhole()
    {
        const string digest = "sha512-7mJJl+wf1AByoT0PknQiQfOPnVNT4fevGrUBVWO4HXsnYn1aQPyRyrELYrNUFleUBM++KzMKN6QaxHPk0t/6/g==";
        var filler = new string(' ', (64 * 1024) - 74); // the limit falls 60 characters into the digest

        var result = await AnalyzeAsync($"{filler}\"integrity\": \"{digest}\" and more");

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
