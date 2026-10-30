using Microsoft.Extensions.AI;
using AI.Sentinel.Audit;
using AI.Sentinel.ClaudeCode;
using AI.Sentinel.Detection;
using AI.Sentinel.Detectors.Compliance;
using AI.Sentinel.Intervention;

namespace AI.Sentinel.Mcp;

/// <summary>Builds a <see cref="SentinelPipeline"/> wired for MCP-proxy use.</summary>
/// <remarks>
/// The proxy only calls <see cref="SentinelPipeline.ScanMessagesAsync"/> and
/// <see cref="SentinelPipeline.RedactAndScanAsync"/>, so the
/// inner <see cref="IChatClient"/> is never invoked — a stub that throws on use
/// is wired in to keep the constructor happy.
/// </remarks>
internal static class McpPipelineFactory
{
    public static SentinelPipeline Create(HookConfig config, DetectorPreset preset,
        IEmbeddingGenerator<string, Embedding<float>>? embeddingGenerator = null)
        => Create(config, preset, embeddingGenerator, out _, out _);

    /// <summary>
    /// Same as <see cref="Create(HookConfig, DetectorPreset, IEmbeddingGenerator{string, Embedding{float}}?)"/>
    /// but also exposes the underlying <see cref="IAuditStore"/> so the proxy can route
    /// out-of-band entries (e.g. authorization denials) to the same ring buffer.
    /// </summary>
    public static SentinelPipeline Create(
        HookConfig config,
        DetectorPreset preset,
        IEmbeddingGenerator<string, Embedding<float>>? embeddingGenerator,
        out IAuditStore auditStore)
        => Create(config, preset, embeddingGenerator, out auditStore, out _);

    /// <summary>As above, also reporting whether semantic detection is inert — this host registers no
    /// logging provider, so the proxy writes the warning to stderr itself (#170).</summary>
    public static SentinelPipeline Create(
        HookConfig config,
        DetectorPreset preset,
        IEmbeddingGenerator<string, Embedding<float>>? embeddingGenerator,
        out IAuditStore auditStore,
        out string? inertSemanticWarning,
        IEmbeddingCache? exampleEmbeddingCache = null,
        Action<string>? detectorFailureSink = null,
        IAuditStore? suppliedStore = null,
        IReadOnlyList<IAuditForwarder>? forwarders = null)
    {
        ArgumentNullException.ThrowIfNull(config);

        var options = new SentinelOptions
        {
            OnCritical = MapDecision(config.OnCritical),
            OnHigh = MapDecision(config.OnHigh),
            OnMedium = MapDecision(config.OnMedium),
            OnLow = MapDecision(config.OnLow),
            EmbeddingGenerator = embeddingGenerator,
            ExampleEmbeddingCache = exampleEmbeddingCache,
            OnDetectorFailure = detectorFailureSink,
        };
        // The compliance detectors are opt-in (SENTINEL_MCP_COMPLIANCE=on). When on, their findings forward
        // with an audit entry, as Warn does, instead of following OnHigh.
        if (config.EnableComplianceDetectors)
            options.EnableComplianceDetectors();
        options.AlertOnComplianceFindings();

        var detectors = DetectorPresets.Build(preset, options);

        inertSemanticWarning = ServiceCollectionExtensions.DescribeInertSemanticDetection(options, detectors);

        // A supplied store (the CLI's shared local audit file) replaces the in-memory ring buffer.
        var store = suppliedStore ?? new RingBufferAuditStore(capacity: 1024);
        auditStore = store;

        return Assemble(options, detectors, store, detectorFailureSink, forwarders);
    }

    /// <summary>Wires the detectors, store and options into a pipeline. Split out so a test can supply its own detectors.</summary>
    internal static SentinelPipeline Assemble(
        SentinelOptions options,
        IEnumerable<IDetector> detectors,
        IAuditStore store,
        Action<string>? detectorFailureSink = null,
        IReadOnlyList<IAuditForwarder>? forwarders = null)
        => new(
            innerClient: UnusedChatClient.Instance,
            pipeline: new DetectionPipeline(detectors, options.GetDetectorConfigurations(), reviewer: null,
                                    logger: null, onDetectorFailure: detectorFailureSink,
                                    redactByDefault: options.RedactByDefault,
                                    embeddingScope: EmbeddingScope.Resolve(options, inherited: null)),
            auditStore: store,
            interventionEngine: new InterventionEngine(options, mediator: null),
            options: options,
            forwarders: forwarders);

    internal static SentinelAction MapDecision(HookDecision decision) => decision switch
    {
        HookDecision.Block => SentinelAction.Quarantine,
        HookDecision.Warn => SentinelAction.Alert,
        _ => SentinelAction.PassThrough,
    };

    // IChatClient satisfying SentinelPipeline's signature. Never invoked because
    // the proxy uses prompt-only scanning via ScanMessagesAsync.
    private sealed class UnusedChatClient : IChatClient
    {
        public static readonly UnusedChatClient Instance = new();

        public Task<ChatResponse> GetResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, CancellationToken cancellationToken = default)
            => throw new InvalidOperationException("UnusedChatClient should never be invoked — MCP proxy uses prompt-only scanning.");

        public IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, CancellationToken cancellationToken = default)
            => throw new InvalidOperationException("UnusedChatClient should never be invoked — MCP proxy uses prompt-only scanning.");

        public object? GetService(Type serviceType, object? serviceKey = null) => null;

        public void Dispose() { }
    }
}
