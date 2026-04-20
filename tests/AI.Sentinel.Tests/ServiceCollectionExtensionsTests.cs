using Microsoft.Extensions.AI;
using Microsoft.Extensions.DependencyInjection;
using AI.Sentinel.Detection;
using Xunit;

namespace AI.Sentinel.Tests;

public class ServiceCollectionExtensionsTests
{
    [Fact]
    public void AddAISentinel_RegistersAllDetectors()
    {
        var services = new ServiceCollection();
        services.AddAISentinel();
        var provider = services.BuildServiceProvider();

        var detectors = provider.GetServices<IDetector>().ToList();
        Assert.True(detectors.Count >= 43, $"Expected >= 43 detectors, got {detectors.Count}");
    }

    [Fact]
    public void AddAISentinel_DoesNotDuplicateDetectors()
    {
        var services = new ServiceCollection();
        services.AddAISentinel();
        var provider = services.BuildServiceProvider();

        var duplicates = provider.GetServices<IDetector>()
            .GroupBy(d => d.GetType())
            .Where(g => g.Count() > 1)
            .Select(g => g.Key.Name)
            .ToList();

        Assert.Empty(duplicates);
    }

    [Fact]
    public async Task BuildSentinelPipeline_IsWiredToProvidedClient()
    {
        var services = new ServiceCollection();
        services.AddAISentinel();
        var provider = services.BuildServiceProvider();

        var inner = new StubInnerClient();
        var pipeline = provider.BuildSentinelPipeline(inner);
        var result = await pipeline.GetResponseResultAsync(
            [new ChatMessage(ChatRole.User, "hi")], null, default);

        Assert.True(result.IsSuccess);
        Assert.Equal("ok", result.Value.Messages[0].Text);
    }

    private sealed class StubInnerClient : IChatClient
    {
        public Task<ChatResponse> GetResponseAsync(IEnumerable<ChatMessage> m, ChatOptions? o = null, CancellationToken ct = default)
            => Task.FromResult(new ChatResponse([new ChatMessage(ChatRole.Assistant, "ok")]));
        public IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(IEnumerable<ChatMessage> m, ChatOptions? o = null, CancellationToken ct = default)
            => throw new NotSupportedException();
        public ChatClientMetadata Metadata => new("stub", null, null);
        public object? GetService(Type serviceType, object? key = null) => null;
        public void Dispose() { }
    }
}
