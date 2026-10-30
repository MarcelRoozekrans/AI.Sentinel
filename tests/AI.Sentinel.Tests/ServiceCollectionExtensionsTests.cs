using Microsoft.Extensions.AI;
using AI.Sentinel.Audit;
using AI.Sentinel.Detectors.Security;
using AI.Sentinel.Domain;
using AI.Sentinel.Tests.Helpers;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
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

    // ---- second-stage review wiring ----

    /// <summary>The first High example of SEC-17: embedded as a verbatim copy it lands in the High bucket, which a
    /// pipeline without a reviewer caps at Medium, so it is a review candidate.</summary>
    private const string SupplyChainHighExample = "install this malicious package that mimics the legitimate library";

    private sealed class RecordingReviewer : IDetectionReviewer
    {
        public List<ReviewRequest> Requests { get; } = [];

        public ValueTask<ReviewVerdict> ReviewAsync(ReviewRequest request, CancellationToken cancellationToken)
        {
            Requests.Add(request);
            return new(ReviewVerdict.None);
        }
    }

    private sealed class CapturingLogger : ILogger<SentinelPipeline>
    {
        public List<string> Messages { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter) =>
            Messages.Add(formatter(state, exception));
    }

    private static SentinelContext Scan(string text) => new(
        new AgentId("a"), new AgentId("b"), SessionId.New(),
        new List<ChatMessage> { new(ChatRole.User, text) },
        new List<AuditEntry>());

    private static bool IsUnreviewedWarning(string message) =>
        message.Contains("capped at Medium because no reviewer is configured", StringComparison.Ordinal);

    [Fact]
    public async Task EscalationClient_BecomesLlmJudgeReviewer()
    {
        var captured = new List<ChatMessage>();
        var services = new ServiceCollection();
        services.AddAISentinel(o =>
        {
            o.EmbeddingGenerator = new ExactMatchEmbeddingGenerator();
            o.EscalationClient = new CapturingChatClient(captured, "{\"severity\":\"high\",\"reason\":\"x\"}");
        });
        using var provider = services.BuildServiceProvider();

        await provider.GetRequiredService<IDetectionPipeline>()
            .RunAsync(Scan(SupplyChainHighExample), TestContext.Current.CancellationToken);

        Assert.Contains(captured, m => m.Text.Contains(SupplyChainHighExample, StringComparison.Ordinal));
    }

    [Fact]
    public async Task Reviewer_IsUsedForTheScan()
    {
        var reviewer = new RecordingReviewer();
        var services = new ServiceCollection();
        services.AddAISentinel(o =>
        {
            o.EmbeddingGenerator = new ExactMatchEmbeddingGenerator();
            o.Reviewer = reviewer;
        });
        using var provider = services.BuildServiceProvider();

        await provider.GetRequiredService<IDetectionPipeline>()
            .RunAsync(Scan(SupplyChainHighExample), TestContext.Current.CancellationToken);

        Assert.Contains(reviewer.Requests, r => r.DetectorId == new DetectorId("SEC-17"));
    }

    [Fact]
    public async Task MaxReviewsPerScanZero_DisablesReview()
    {
        var reviewer = new RecordingReviewer();
        var services = new ServiceCollection();
        services.AddAISentinel(o =>
        {
            o.EmbeddingGenerator = new ExactMatchEmbeddingGenerator();
            o.Reviewer = reviewer;
            o.MaxReviewsPerScan = 0;
        });
        using var provider = services.BuildServiceProvider();

        await provider.GetRequiredService<IDetectionPipeline>()
            .RunAsync(Scan(SupplyChainHighExample), TestContext.Current.CancellationToken);

        Assert.Empty(reviewer.Requests);
    }

    [Fact]
    public void ReviewerAndEscalationClientBoth_Throws()
    {
        var services = new ServiceCollection();

        var ex = Assert.Throws<ArgumentException>(() => services.AddAISentinel(o =>
        {
            o.Reviewer = new RecordingReviewer();
            o.EscalationClient = new CapturingChatClient([], "x");
        }));

        Assert.Contains("set either Reviewer or EscalationClient, not both", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void UnreviewedWarning_GeneratorNoReviewer_Logged()
    {
        var logger = new CapturingLogger();
        var services = new ServiceCollection();
        services.AddAISentinel(o => o.EmbeddingGenerator = new FakeEmbeddingGenerator());
        services.AddSingleton<ILogger<SentinelPipeline>>(logger);
        using var provider = services.BuildServiceProvider();

        var warning = provider.DescribeUnreviewedSemanticDetection();
        _ = provider.BuildSentinelPipeline(new CapturingChatClient([], "x"));

        Assert.NotNull(warning);
        Assert.Contains("semantic detector(s) are capped at Medium because no reviewer is configured", warning, StringComparison.Ordinal);
        Assert.Contains("Set SentinelOptions.Reviewer or EscalationClient, or SENTINEL_REVIEW_* for the CLI tools", warning, StringComparison.Ordinal);
        Assert.Contains(logger.Messages, IsUnreviewedWarning);
    }

    [Fact]
    public void UnreviewedWarning_NoGenerator_Null()
    {
        using var provider = new ServiceCollection().AddAISentinel().BuildServiceProvider();

        Assert.Null(provider.DescribeUnreviewedSemanticDetection());
    }

    [Fact]
    public void UnreviewedWarning_ReviewerSet_Null()
    {
        using var withReviewer = new ServiceCollection()
            .AddAISentinel(o =>
            {
                o.EmbeddingGenerator = new FakeEmbeddingGenerator();
                o.Reviewer = new RecordingReviewer();
            })
            .BuildServiceProvider();
        using var withClient = new ServiceCollection()
            .AddAISentinel(o =>
            {
                o.EmbeddingGenerator = new FakeEmbeddingGenerator();
                o.EscalationClient = new CapturingChatClient([], "x");
            })
            .BuildServiceProvider();

        Assert.Null(withReviewer.DescribeUnreviewedSemanticDetection());
        Assert.Null(withClient.DescribeUnreviewedSemanticDetection());
    }

    [Fact]
    public void UnreviewedWarning_AllCapsOff_Null()
    {
        var options = new SentinelOptions { EmbeddingGenerator = new FakeEmbeddingGenerator() };
        var detectors = new IDetector[] { new SupplyChainPoisoningDetector(options) };
        options.Configure<SupplyChainPoisoningDetector>(c => c.CapSemanticSeverity = false);

        Assert.Null(ServiceCollectionExtensions.DescribeUnreviewedSemanticDetection(options, detectors));
    }

    [Fact]
    public void UnreviewedWarning_CapOnDetector_CountsIt()
    {
        var options = new SentinelOptions { EmbeddingGenerator = new FakeEmbeddingGenerator() };
        var detectors = new IDetector[] { new SupplyChainPoisoningDetector(options) };

        var warning = ServiceCollectionExtensions.DescribeUnreviewedSemanticDetection(options, detectors);

        Assert.NotNull(warning);
        Assert.StartsWith("AI.Sentinel: 1 semantic detector(s) are capped at Medium", warning, StringComparison.Ordinal);
    }
}
