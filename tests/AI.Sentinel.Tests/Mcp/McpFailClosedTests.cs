using AI.Sentinel.Mcp;
using Microsoft.Extensions.AI;
using Xunit;
using static AI.Sentinel.Tests.Mcp.McpFailClosedFixture;

namespace AI.Sentinel.Tests.Mcp;

public class McpFailClosedTests
{
    [Fact]
    public void Block_NamesTheTypeOnly()
        => AssertFailClosed(McpFailClosed.Block(new InvalidOperationException(LeakMarker)));

    [Fact]
    public async Task ThrowingPipeline_DelegatesBeforeThrowFromCall()
    {
        var pipeline = ThrowingPipeline(throwFromCall: 2);
        var messages = new[] { new ChatMessage(ChatRole.User, "hello") };
        var ct = TestContext.Current.CancellationToken;

        var first = await pipeline.ScanMessagesAsync(messages, ct: ct);
        Assert.Null(first);

        await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await pipeline.ScanMessagesAsync(messages, ct: ct));
    }
}
