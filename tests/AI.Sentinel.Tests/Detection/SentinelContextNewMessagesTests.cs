using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using Microsoft.Extensions.AI;
using Xunit;

namespace AI.Sentinel.Tests.Detection;

// #424. NewMessagesFrom marks where the messages new in a scan start; out-of-range values are clamped.
public class SentinelContextNewMessagesTests
{
    private static SentinelContext Context(int? newMessagesFrom = null)
    {
        ChatMessage[] messages =
        [
            new(ChatRole.User, "a"),
            new(ChatRole.User, "b"),
            new(ChatRole.User, "c"),
        ];
        return newMessagesFrom is { } from
            ? new SentinelContext(new AgentId("s"), new AgentId("r"), SessionId.New(), messages, []) { NewMessagesFrom = from }
            : new SentinelContext(new AgentId("s"), new AgentId("r"), SessionId.New(), messages, []);
    }

    [Fact]
    public void NewMessagesFrom_DefaultsToZero()
    {
        var ctx = Context();
        Assert.Equal(0, ctx.NewMessagesFrom);
    }

    [Fact]
    public void NewMessagesFrom_AboveCount_IsClampedToCount()
        => Assert.Equal(3, Context(99).NewMessagesFrom);

    [Fact]
    public void NewMessagesFrom_Negative_IsClampedToZero()
        => Assert.Equal(0, Context(-1).NewMessagesFrom);
}
