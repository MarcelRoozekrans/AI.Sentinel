using System.Text;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using Microsoft.Extensions.AI;
using Xunit;

namespace AI.Sentinel.Tests.Detection;

// #439. MaxScanBytes bounds the UTF-8 bytes of the new messages' detection text; the cut view is exposed
// as NewMessageTexts, NewTextContent and NewProseContent, and oversize is reported by ExceedsScanBudget.
public class SentinelContextScanBudgetTests
{
    private static SentinelContext Context(int? maxScanBytes, int newMessagesFrom = 0, params string[] texts) =>
        Context(maxScanBytes, newMessagesFrom, texts.Select(t => new ChatMessage(ChatRole.User, t)).ToArray());

    private static SentinelContext Context(int? maxScanBytes, int newMessagesFrom, ChatMessage[] messages) =>
        new(new AgentId("s"), new AgentId("r"), SessionId.New(), messages, [])
        {
            NewMessagesFrom = newMessagesFrom,
            MaxScanBytes = maxScanBytes,
        };

    [Fact]
    public void NewMessageTexts_HoldsOnlyMessagesFromNewMessagesFrom()
    {
        var ctx = Context(null, 2, "one", "two", "three");

        Assert.Equal(["three"], ctx.NewMessageTexts);
        Assert.Equal("three", ctx.NewTextContent);
    }

    [Fact]
    public void NoBudget_NothingIsCut()
    {
        var text = new string('a', 1_000_000);
        var ctx = Context(null, 0, text);

        Assert.False(ctx.ExceedsScanBudget);
        Assert.Equal(1_000_000, ctx.NewContentBytes);
        Assert.Same(text, ctx.NewMessageTexts[0]);
    }

    [Fact]
    public void ExactlyAtBudget_IsNotOversize()
    {
        var ctx = Context(10, 0, "aaaaaa", "bbbb");

        Assert.False(ctx.ExceedsScanBudget);
        Assert.Equal(["aaaaaa", "bbbb"], ctx.NewMessageTexts);
        Assert.Equal("aaaaaa bbbb", ctx.NewTextContent);
    }

    [Fact]
    public void OverBudget_CutsInMessageOrder()
    {
        var ctx = Context(8, 0, "aaaaaa", "bbbbbb");

        Assert.Equal(["aaaaaa", "bb"], ctx.NewMessageTexts);
        Assert.Equal(12, ctx.NewContentBytes);
        Assert.True(ctx.ExceedsScanBudget);
        Assert.Equal("aaaaaa bb", ctx.NewTextContent);
    }

    [Fact]
    public void PastBudget_LaterMessagesAreEmpty()
    {
        var ctx = Context(5, 0, "xxxxx", "yyyyy", "zzzzz");

        Assert.Equal(["xxxxx", "", ""], ctx.NewMessageTexts);
    }

    [Fact]
    public void Cut_NeverSplitsSurrogatePair()
    {
        Assert.Equal(["ab"], Context(4, 0, "ab😀").NewMessageTexts);
        Assert.Equal(["ab😀"], Context(6, 0, "ab😀").NewMessageTexts);
    }

    [Fact]
    public void Cut_MultiByteCjk()
    {
        Assert.Equal(["日本"], Context(7, 0, "日本語").NewMessageTexts);
    }

    [Fact]
    public void ToolResultCountsTowardBudget()
    {
        var result = new string('r', 100);
        var tool = new ChatMessage(ChatRole.Tool, [new FunctionResultContent("c1", result)]);
        var ctx = Context(50, 0, [tool]);

        Assert.True(ctx.ExceedsScanBudget);
        Assert.Equal(100, ctx.NewContentBytes);
        Assert.Equal(50, Encoding.UTF8.GetByteCount(ctx.NewMessageTexts[0]));
    }

    [Fact]
    public void NewProseContent_ExcludesToolTraffic()
    {
        ChatMessage[] messages =
        [
            new(ChatRole.Assistant, "hello"),
            new(ChatRole.Tool, [new FunctionResultContent("c1", "secret tool output")]),
        ];
        var ctx = Context(null, 0, messages);

        Assert.Equal("hello ", ctx.NewProseContent);
        Assert.Contains("secret tool output", ctx.NewTextContent);
    }

    [Fact]
    public void NewProseContent_IsCutIndependently()
    {
        var ctx = Context(8, 0, "aaaaaa", "bbbbbb");

        Assert.Equal("aaaaaa bb", ctx.NewProseContent);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void ZeroOrNegativeBudget_Throws(int budget)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => Context(budget, 0, "a"));
    }

    [Fact]
    public void Truncate_ReturnsSameInstanceWhenItFits()
    {
        var text = "abc";
        Assert.Same(text, Utf8Text.Truncate(text, 3));
        Assert.Equal("", Utf8Text.Truncate(text, 0));
    }
}
