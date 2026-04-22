using Xunit;
using Microsoft.Extensions.AI;
using AI.Sentinel.Cli;

namespace AI.Sentinel.Tests.Replay;

public class SentinelReplayClientTests
{
    [Fact]
    public async Task GetResponseAsync_ReturnsNextRecorded()
    {
        var responses = new List<ChatMessage>
        {
            new(ChatRole.Assistant, "first"),
            new(ChatRole.Assistant, "second"),
        };
        var client = new SentinelReplayClient(responses);

        var r1 = await client.GetResponseAsync([new ChatMessage(ChatRole.User, "q1")]);
        var r2 = await client.GetResponseAsync([new ChatMessage(ChatRole.User, "q2")]);

        Assert.Equal("first", r1.Messages[0].Text);
        Assert.Equal("second", r2.Messages[0].Text);
    }

    [Fact]
    public async Task GetResponseAsync_Exhausted_Throws()
    {
        var client = new SentinelReplayClient([new ChatMessage(ChatRole.Assistant, "only")]);
        _ = await client.GetResponseAsync([new ChatMessage(ChatRole.User, "q1")]);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => client.GetResponseAsync([new ChatMessage(ChatRole.User, "q2")]));
    }

    [Fact]
    public void GetStreamingResponseAsync_Throws()
    {
        var client = new SentinelReplayClient([new ChatMessage(ChatRole.Assistant, "x")]);
        Assert.Throws<NotSupportedException>(
            () => client.GetStreamingResponseAsync([new ChatMessage(ChatRole.User, "q")]));
    }
}
