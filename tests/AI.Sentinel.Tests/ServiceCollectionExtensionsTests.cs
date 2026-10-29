using Microsoft.Extensions.AI;
using Microsoft.Extensions.DependencyInjection;
using AI.Sentinel.Alerts;
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
            [new ChatMessage(ChatRole.User, "hi")], null, TestContext.Current.CancellationToken);

        Assert.True(result.IsSuccess);
        Assert.Equal("ok", result.Value.Messages[0].Text);
    }

    [Fact]
    public void AddAISentinel_NoAlertWebhook_RegistersNullAlertSink()
    {
        var services = new ServiceCollection();
        services.AddAISentinel();
        var provider = services.BuildServiceProvider();

        var sink = provider.GetRequiredService<IAlertSink>();
        Assert.IsType<DeduplicatingAlertSink>(sink);
    }

    [Fact]
    public void AddAISentinel_WithAlertWebhook_RegistersWebhookAlertSink()
    {
        var services = new ServiceCollection();
        services.AddAISentinel(opts => opts.AlertWebhook = new Uri("http://example.com/hook"));
        var provider = services.BuildServiceProvider();

        var sink = provider.GetRequiredService<IAlertSink>();
        Assert.IsType<DeduplicatingAlertSink>(sink);
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

    [Fact]
    public void AddAISentinel_DefaultCalledTwice_Throws()
    {
        var services = new ServiceCollection();
        services.AddAISentinel();

        var ex = Assert.Throws<InvalidOperationException>(() => services.AddAISentinel(o => { }));

        Assert.Equal("The default AI.Sentinel pipeline is already registered.", ex.Message);
    }

    [Fact]
    public void AddAISentinel_DefaultCalledTwice_DoesNotAddSecondSetOfSingletons()
    {
        var services = new ServiceCollection();
        services.AddAISentinel();
        var count = services.Count;

        Assert.Throws<InvalidOperationException>(() => services.AddAISentinel());

        Assert.Equal(count, services.Count);
    }

    [Fact]
    public void AddAISentinel_DefaultThenNamed_BothRegister()
    {
        var services = new ServiceCollection();
        services.AddAISentinel();
        services.AddAISentinel("strict", o => { });

        using var provider = services.BuildServiceProvider();
        Assert.NotNull(provider.GetRequiredService<IDetectionPipeline>());
        Assert.NotNull(provider.GetRequiredKeyedService<IDetectionPipeline>("strict"));
    }

    [Fact]
    public void AddAISentinel_NamedThenDefault_BothRegister()
    {
        var services = new ServiceCollection();
        services.AddAISentinel("strict", o => { });
        services.AddAISentinel();

        using var provider = services.BuildServiceProvider();
        Assert.NotNull(provider.GetRequiredService<IDetectionPipeline>());
        Assert.NotNull(provider.GetRequiredKeyedService<IDetectionPipeline>("strict"));
    }
}
