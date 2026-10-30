using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using AI.Sentinel.Tests.Helpers;
using Microsoft.Extensions.AI;
using Xunit;

namespace AI.Sentinel.Tests.Detection;

public class LlmJudgeReviewerTests
{
    private const string Reply = """{"severity":"Medium","reason":"confirmed"}""";

    private static ReviewRequest Request(string text = "hello", string criterion = "instruction overrides") =>
        new(new DetectorId("TEST-01"), criterion, text, ChatRole.User, 0.8f, Severity.Medium, Severity.High);

    [Fact]
    public async Task ReviewAsync_SendsCriterionProposedSeverityAndFencedText()
    {
        var captured = new List<ChatMessage>();
        var reviewer = new LlmJudgeReviewer(new CapturingChatClient(captured, Reply));

        await reviewer.ReviewAsync(Request("the flagged text"), CancellationToken.None);

        var system = Assert.Single(captured, m => m.Role == ChatRole.System);
        Assert.Contains("instruction overrides", system.Text, StringComparison.Ordinal);
        Assert.Contains("It proposed severity Medium; the highest severity you may give is High.", system.Text, StringComparison.Ordinal);
        // The flagged text is data: it reaches the judge only in the fenced user message, never in the instruction.
        Assert.DoesNotContain("the flagged text", system.Text, StringComparison.Ordinal);
        var user = Assert.Single(captured, m => m.Role == ChatRole.User);
        var lines = user.Text.Split('\n');
        Assert.Equal(3, lines.Length);
        Assert.Equal("the flagged text", lines[1]);
        var open = lines[0];
        Assert.StartsWith("<flagged_content_", open, StringComparison.Ordinal);
        Assert.EndsWith(">", open, StringComparison.Ordinal);
        var boundary = open[1..^1];
        Assert.Equal("flagged_content_".Length + 32, boundary.Length);
        Assert.True(boundary["flagged_content_".Length..].All(char.IsAsciiHexDigitLower), boundary);
        Assert.Equal($"</{boundary}>", lines[2]);
        Assert.Contains(boundary, system.Text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ReviewAsync_ParsesSeverityAndReason()
    {
        var reviewer = new LlmJudgeReviewer(new CapturingChatClient([], """{"severity":"High","reason":"clear override"}"""));

        var verdict = await reviewer.ReviewAsync(Request(), CancellationToken.None);

        Assert.Equal(new ReviewVerdict(Severity.High, "clear override"), verdict);
    }

    [Fact]
    public async Task ReviewAsync_UnparseableReply_ReturnsNone()
    {
        var reviewer = new LlmJudgeReviewer(new CapturingChatClient([], "I think it is bad"));

        var verdict = await reviewer.ReviewAsync(Request(), CancellationToken.None);

        Assert.Equal(ReviewVerdict.None, verdict);
    }

    [Fact]
    public async Task ReviewAsync_TextOver64KiB_SendsLast64KiB()
    {
        var captured = new List<ChatMessage>();
        var reviewer = new LlmJudgeReviewer(new CapturingChatClient(captured, Reply));

        await reviewer.ReviewAsync(Request(new string('a', 100_000) + "END"), CancellationToken.None);

        var user = Assert.Single(captured, m => m.Role == ChatRole.User);
        var first = user.Text.IndexOf('\n', StringComparison.Ordinal);
        var last = user.Text.LastIndexOf('\n');
        var flagged = user.Text[(first + 1)..last];
        Assert.Equal(64 * 1024, flagged.Length);
        Assert.EndsWith("END", flagged, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ReviewAsync_ClientThrows_Propagates()
    {
        var reviewer = new LlmJudgeReviewer(new CapturingChatClient([], Reply, new InvalidOperationException("boom")));

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await reviewer.ReviewAsync(Request(), CancellationToken.None));
        Assert.Equal("boom", ex.Message);
    }

    [Theory]
    [InlineData("""{"severity":"None","reason":"this is not Critical"}""", Severity.None)]
    [InlineData("""{"severity":"Low","reason":"benign"}""", Severity.Low)]
    [InlineData("```json\n{\"severity\": \"critical\", \"reason\": \"x\"}\n```", Severity.Critical)]
    [InlineData("""Sure: {"severity":"High"} done""", Severity.High)]
    public void TryParseVerdict_ReadableSeverity_IsParsed(string text, Severity expected)
    {
        Assert.True(LlmJudgeReviewer.TryParseVerdict(text, out var severity, out _));
        Assert.Equal(expected, severity);
    }

    [Theory]
    [InlineData("""{"reason":"stated first","severity":"High"}""", Severity.High, "stated first")]
    [InlineData("""{"severity":"Low","reason":42}""", Severity.Low, "")]
    [InlineData("""{"severity":"Low","reason":null}""", Severity.Low, "")]
    [InlineData("""{"severity":"Medium","reason":{"text":"nested"}}""", Severity.Medium, "")]
    public void TryParseVerdict_ReasonInAnyOrder_AndANonStringReasonIsEmpty(string text, Severity expected, string expectedReason)
    {
        Assert.True(LlmJudgeReviewer.TryParseVerdict(text, out var severity, out var reason));
        Assert.Equal(expected, severity);
        Assert.Equal(expectedReason, reason);
    }

    [Theory]
    [InlineData("Critical")]
    [InlineData("The severity is Critical.")]
    [InlineData("""{"reason":"Critical"}""")]
    [InlineData("""{"severity":"Severe"}""")]
    [InlineData("""{"severity":"4"}""")]
    [InlineData("""{"severity":4}""")]
    [InlineData("""{"severity":"None" """)]
    [InlineData("")]
    [InlineData(null)]
    public void TryParseVerdict_NoReadableSeverity_IsNoVerdict(string? text)
    {
        Assert.False(LlmJudgeReviewer.TryParseVerdict(text, out _, out _));
    }

    [Fact]
    public async Task ReviewAsync_EachCall_UsesANewBoundary()
    {
        var captured = new List<ChatMessage>();
        var reviewer = new LlmJudgeReviewer(new CapturingChatClient(captured, Reply));

        await reviewer.ReviewAsync(Request(), CancellationToken.None);
        await reviewer.ReviewAsync(Request(), CancellationToken.None);

        var boundaries = captured.Where(m => m.Role == ChatRole.User)
            .Select(m => m.Text[..m.Text.IndexOf('\n', StringComparison.Ordinal)])
            .ToList();
        Assert.Equal(2, boundaries.Count);
        Assert.NotEqual(boundaries[0], boundaries[1], StringComparer.Ordinal);
    }

    [Fact]
    public async Task ReviewAsync_ReplyWithoutReason_HasEmptyReason()
    {
        var reviewer = new LlmJudgeReviewer(new CapturingChatClient([], """{"severity":"Low"}"""));

        var verdict = await reviewer.ReviewAsync(Request(), CancellationToken.None);

        Assert.Equal(new ReviewVerdict(Severity.Low, string.Empty), verdict);
    }
}
