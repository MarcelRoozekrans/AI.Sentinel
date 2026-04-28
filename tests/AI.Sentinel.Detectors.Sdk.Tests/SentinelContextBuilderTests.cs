using AI.Sentinel.Detectors.Sdk;
using AI.Sentinel.Domain;
using Microsoft.Extensions.AI;
using Xunit;

namespace AI.Sentinel.Detectors.Sdk.Tests;

public class SentinelContextBuilderTests
{
    [Fact]
    public void Build_DefaultsApplied_WhenNoSettersCalled()
    {
        var ctx = new SentinelContextBuilder().Build();

        Assert.NotNull(ctx);
        Assert.Empty(ctx.Messages);
        Assert.Empty(ctx.History);
        Assert.Equal("user", ctx.SenderId.Value, StringComparer.Ordinal);
        Assert.Equal("assistant", ctx.ReceiverId.Value, StringComparer.Ordinal);
        Assert.NotNull(ctx.SessionId);
        Assert.Null(ctx.LlmId);
    }

    [Fact]
    public void WithUserMessage_AppendsChatRoleUser()
    {
        var ctx = new SentinelContextBuilder()
            .WithUserMessage("hello")
            .Build();

        Assert.Single(ctx.Messages);
        Assert.Equal(ChatRole.User, ctx.Messages[0].Role);
        Assert.Equal("hello", ctx.Messages[0].Text, StringComparer.Ordinal);
    }

    [Fact]
    public void WithMultipleMessages_PreservedInOrder()
    {
        var ctx = new SentinelContextBuilder()
            .WithUserMessage("first")
            .WithAssistantMessage("second")
            .WithToolMessage("third")
            .Build();

        Assert.Equal(3, ctx.Messages.Count);
        Assert.Equal(ChatRole.User, ctx.Messages[0].Role);
        Assert.Equal(ChatRole.Assistant, ctx.Messages[1].Role);
        Assert.Equal(ChatRole.Tool, ctx.Messages[2].Role);
    }

    [Fact]
    public void WithSession_OverridesDefault()
    {
        var session = new SessionId("custom-session");
        var ctx = new SentinelContextBuilder().WithSession(session).Build();

        Assert.Equal("custom-session", ctx.SessionId.Value, StringComparer.Ordinal);
    }
}
