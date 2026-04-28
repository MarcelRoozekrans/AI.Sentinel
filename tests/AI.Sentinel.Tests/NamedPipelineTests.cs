using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using AI.Sentinel.Detectors.Security;
using AI.Sentinel.Domain;
using AI.Sentinel.Intervention;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AI.Sentinel.Tests;

public class NamedPipelineTests
{
    [Fact]
    public void AddAISentinel_NullName_ThrowsArgumentNullException()
    {
        var services = new ServiceCollection();
        Assert.Throws<ArgumentNullException>(() =>
            services.AddAISentinel(name: null!, opts => { }));
    }

    [Fact]
    public void AddAISentinel_EmptyName_ThrowsArgumentException()
    {
        var services = new ServiceCollection();
        Assert.Throws<ArgumentException>(() =>
            services.AddAISentinel(name: "", opts => { }));
    }

    [Fact]
    public void AddAISentinel_WhitespaceName_ThrowsArgumentException()
    {
        var services = new ServiceCollection();
        Assert.Throws<ArgumentException>(() =>
            services.AddAISentinel(name: "   ", opts => { }));
    }

    [Fact]
    public void AddAISentinel_DuplicateName_ThrowsInvalidOperationException()
    {
        var services = new ServiceCollection();
        services.AddAISentinel("strict", opts => { });
        var ex = Assert.Throws<InvalidOperationException>(() =>
            services.AddAISentinel("strict", opts => { }));
        Assert.Contains("strict", ex.Message, StringComparison.Ordinal);
        Assert.Contains("already registered", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AddAISentinel_Named_RegistersIsolatedSentinelOptions()
    {
        var services = new ServiceCollection();
        services.AddAISentinel(opts => opts.AuditCapacity = 100);  // default unnamed
        services.AddAISentinel("strict", opts => opts.AuditCapacity = 200);
        services.AddAISentinel("lenient", opts => opts.AuditCapacity = 300);

        var sp = services.BuildServiceProvider();
        var defaultOpts = sp.GetRequiredService<SentinelOptions>();
        var strictOpts = sp.GetRequiredKeyedService<SentinelOptions>("strict");
        var lenientOpts = sp.GetRequiredKeyedService<SentinelOptions>("lenient");

        Assert.Equal(100, defaultOpts.AuditCapacity);
        Assert.Equal(200, strictOpts.AuditCapacity);
        Assert.Equal(300, lenientOpts.AuditCapacity);
        Assert.NotSame(defaultOpts, strictOpts);
        Assert.NotSame(strictOpts, lenientOpts);
    }

    [Fact]
    public void AddAISentinel_Named_DefaultPipelineUnaffected()
    {
        var services = new ServiceCollection();
        services.AddAISentinel(opts => opts.AuditCapacity = 100);
        services.AddAISentinel("strict", opts => opts.AuditCapacity = 999);

        var sp = services.BuildServiceProvider();
        Assert.Equal(100, sp.GetRequiredService<SentinelOptions>().AuditCapacity);
        Assert.NotNull(sp.GetRequiredService<IDetectionPipeline>());
    }

    [Fact]
    public void UseAISentinel_NamedResolvesKeyedPipeline()
    {
        var services = new ServiceCollection();
        services.AddAISentinel(opts => opts.AuditCapacity = 100);
        services.AddAISentinel("strict", opts => opts.AuditCapacity = 999);

        var sp = services.BuildServiceProvider();
        var opts = sp.GetRequiredKeyedService<SentinelOptions>("strict");
        var pipeline = sp.GetRequiredKeyedService<IDetectionPipeline>("strict");
        var engine = sp.GetRequiredKeyedService<InterventionEngine>("strict");

        Assert.Equal(999, opts.AuditCapacity);
        Assert.NotNull(pipeline);
        Assert.NotNull(engine);
    }

    [Fact]
    public void UseAISentinel_UnknownName_FailsToResolveKeyedService()
    {
        var services = new ServiceCollection();
        services.AddAISentinel(opts => { });
        var sp = services.BuildServiceProvider();

        Assert.Throws<InvalidOperationException>(() =>
            sp.GetRequiredKeyedService<IDetectionPipeline>("never-registered"));
    }

    [Fact]
    public void UseAISentinel_UnnamedStillResolvesDefaultPipeline()
    {
        var services = new ServiceCollection();
        services.AddAISentinel(opts => opts.AuditCapacity = 42);
        services.AddAISentinel("strict", opts => opts.AuditCapacity = 999);
        var sp = services.BuildServiceProvider();

        Assert.Equal(42, sp.GetRequiredService<SentinelOptions>().AuditCapacity);
    }

    [Fact]
    public void Named_ConfigureT_AppliesPerPipeline()
    {
        var services = new ServiceCollection();
        services.AddAISentinel(opts => { });
        services.AddAISentinel("strict", opts =>
            opts.Configure<JailbreakDetector>(c => c.SeverityFloor = Severity.High));
        services.AddAISentinel("lenient", opts =>
            opts.Configure<JailbreakDetector>(c => c.Enabled = false));

        var sp = services.BuildServiceProvider();
        var strictOpts = sp.GetRequiredKeyedService<SentinelOptions>("strict");
        var lenientOpts = sp.GetRequiredKeyedService<SentinelOptions>("lenient");

        var strictCfg = strictOpts.GetDetectorConfigurations()[typeof(JailbreakDetector)];
        var lenientCfg = lenientOpts.GetDetectorConfigurations()[typeof(JailbreakDetector)];

        Assert.Equal(Severity.High, strictCfg.SeverityFloor);
        Assert.True(strictCfg.Enabled);
        Assert.Null(lenientCfg.SeverityFloor);
        Assert.False(lenientCfg.Enabled);

        var defaultOpts = sp.GetRequiredService<SentinelOptions>();
        Assert.False(defaultOpts.GetDetectorConfigurations().ContainsKey(typeof(JailbreakDetector)));
    }

    [Fact]
    public void Named_AuditStoreIsShared()
    {
        var services = new ServiceCollection();
        services.AddAISentinel(opts => { });
        services.AddAISentinel("strict", opts => { });
        services.AddAISentinel("lenient", opts => { });

        var sp = services.BuildServiceProvider();
        var defaultStore = sp.GetRequiredService<IAuditStore>();
        Assert.Throws<InvalidOperationException>(() => sp.GetRequiredKeyedService<IAuditStore>("strict"));
        Assert.Throws<InvalidOperationException>(() => sp.GetRequiredKeyedService<IAuditStore>("lenient"));
        Assert.NotNull(defaultStore);
    }

    [Fact]
    public void Named_InterventionEngineIsolated()
    {
        var services = new ServiceCollection();
        services.AddAISentinel(opts => opts.OnHigh = SentinelAction.Log);
        services.AddAISentinel("strict", opts => opts.OnHigh = SentinelAction.Quarantine);

        var sp = services.BuildServiceProvider();
        var defaultEngine = sp.GetRequiredService<InterventionEngine>();
        var strictEngine = sp.GetRequiredKeyedService<InterventionEngine>("strict");

        Assert.NotSame(defaultEngine, strictEngine);
    }

    private sealed class AlwaysFiringHighDetector : IDetector
    {
        private static readonly DetectorId _id = new("E2E-NAMED-01");
        public DetectorId Id => _id;
        public DetectorCategory Category => DetectorCategory.Operational;
        public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
            => ValueTask.FromResult(DetectionResult.WithSeverity(_id, Severity.High, "e2e fired"));
    }

    private sealed class NoopChatClient : IChatClient
    {
        public Task<ChatResponse> GetResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, CancellationToken cancellationToken = default)
            => Task.FromResult(new ChatResponse(new ChatMessage(ChatRole.Assistant, "ok")));
        public IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();
        public object? GetService(Type serviceType, object? key = null) => null;
        public void Dispose() { }
    }

    [Fact]
    public async Task EndToEnd_NamedPipelineRoutesThroughSentinelChatClient()
    {
        var services = new ServiceCollection();
        services.AddAISentinel(opts =>
        {
            opts.AddDetector<AlwaysFiringHighDetector>();
            opts.OnHigh = SentinelAction.Log;
        });
        services.AddAISentinel("strict", opts =>
        {
            opts.OnHigh = SentinelAction.Log;
            opts.Configure<AlwaysFiringHighDetector>(c => c.SeverityCap = Severity.Low);
        });

        services.AddChatClient(_ => (IChatClient)new NoopChatClient())
                .UseAISentinel("strict");

        var sp = services.BuildServiceProvider();
        var client = sp.GetRequiredService<IChatClient>();

        await client.GetResponseAsync(new List<ChatMessage> { new(ChatRole.User, "hi") });

        var store = sp.GetRequiredService<IAuditStore>();
        var entries = new List<AuditEntry>();
        await foreach (var e in store.QueryAsync(new AuditQuery(), CancellationToken.None))
        {
            entries.Add(e);
        }

        // Strict pipeline applied SeverityCap = Low to the Always-High firing.
        Assert.Contains(entries, e =>
            string.Equals(e.DetectorId, "E2E-NAMED-01", StringComparison.Ordinal)
            && e.Severity == Severity.Low);
    }
}
