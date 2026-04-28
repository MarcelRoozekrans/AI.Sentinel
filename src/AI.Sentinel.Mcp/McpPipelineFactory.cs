using Microsoft.Extensions.AI;
using AI.Sentinel.Audit;
using AI.Sentinel.ClaudeCode;
using AI.Sentinel.Detection;
using AI.Sentinel.Detectors.Hallucination;
using AI.Sentinel.Detectors.Operational;
using AI.Sentinel.Detectors.Security;
using AI.Sentinel.Intervention;

namespace AI.Sentinel.Mcp;

/// <summary>Builds a <see cref="SentinelPipeline"/> wired for MCP-proxy use.</summary>
/// <remarks>
/// The proxy only calls <see cref="SentinelPipeline.ScanMessagesAsync"/>, so the
/// inner <see cref="IChatClient"/> is never invoked — a stub that throws on use
/// is wired in to keep the constructor happy.
/// </remarks>
internal static class McpPipelineFactory
{
    public static SentinelPipeline Create(HookConfig config, McpDetectorPreset preset,
        IEmbeddingGenerator<string, Embedding<float>>? embeddingGenerator = null)
        => Create(config, preset, embeddingGenerator, out _);

    /// <summary>
    /// Same as <see cref="Create(HookConfig, McpDetectorPreset, IEmbeddingGenerator{string, Embedding{float}}?)"/>
    /// but also exposes the underlying <see cref="IAuditStore"/> so the proxy can route
    /// out-of-band entries (e.g. authorization denials) to the same ring buffer.
    /// </summary>
    public static SentinelPipeline Create(
        HookConfig config,
        McpDetectorPreset preset,
        IEmbeddingGenerator<string, Embedding<float>>? embeddingGenerator,
        out IAuditStore auditStore)
    {
        ArgumentNullException.ThrowIfNull(config);

        var options = new SentinelOptions
        {
            OnCritical         = MapDecision(config.OnCritical),
            OnHigh             = MapDecision(config.OnHigh),
            OnMedium           = MapDecision(config.OnMedium),
            OnLow              = MapDecision(config.OnLow),
            EmbeddingGenerator = embeddingGenerator,
        };

        var detectors = preset switch
        {
            McpDetectorPreset.All => BuildAllDetectors(options),
            _                     => BuildSecurityDetectors(options),
        };

        var ringBuffer = new RingBufferAuditStore(capacity: 1024);
        auditStore = ringBuffer;

        return new SentinelPipeline(
            innerClient:        UnusedChatClient.Instance,
            pipeline:           new DetectionPipeline(detectors, configurations: null, escalationClient: null),
            auditStore:         ringBuffer,
            interventionEngine: new InterventionEngine(options, mediator: null),
            options:            options);
    }

    internal static SentinelAction MapDecision(HookDecision decision) => decision switch
    {
        HookDecision.Block => SentinelAction.Quarantine,
        HookDecision.Warn  => SentinelAction.Alert,
        _                  => SentinelAction.PassThrough,
    };

    // 13 semantic security detectors — mirrors
    // benchmarks/AI.Sentinel.Benchmarks/Harness/PipelineFactory.SecurityOnly().
    internal static IDetector[] BuildSecurityDetectors() => BuildSecurityDetectors(new SentinelOptions());

    internal static IDetector[] BuildSecurityDetectors(SentinelOptions options) =>
    [
        new PromptInjectionDetector(options),
        new JailbreakDetector(options),
        new CredentialExposureDetector(),
        new DataExfiltrationDetector(options),
        new PrivilegeEscalationDetector(options),
        new ToolPoisoningDetector(options),
        new IndirectInjectionDetector(options),
        new AgentImpersonationDetector(options),
        new CovertChannelDetector(options),
        new ToolCallFrequencyDetector(),      // SEC-19
        new ExcessiveAgencyDetector(options),  // SEC-21
        new HumanTrustManipulationDetector(options), // SEC-22
        new ShorthandEmergenceDetector(options),     // SEC-30
    ];

    // 55 detectors — mirror of what AddAISentinel registers via ZeroAllocInject
    // source-gen. Keep these in sync whenever a new detector is decorated with
    // [Singleton(As = typeof(IDetector), AllowMultiple = true)]. The drift-
    // detection test BuildAllDetectors_CountMatchesRegisteredIDetectorCount
    // fails loudly if the list here goes out of sync with the assembly.
    internal static IDetector[] BuildAllDetectors() => BuildAllDetectors(new SentinelOptions());

    internal static IDetector[] BuildAllDetectors(SentinelOptions options) =>
    [
        // Security (31)
        new PromptInjectionDetector(options),
        new JailbreakDetector(options),
        new CredentialExposureDetector(),
        new DataExfiltrationDetector(options),
        new PrivilegeEscalationDetector(options),
        new ToolPoisoningDetector(options),
        new IndirectInjectionDetector(options),
        new AgentImpersonationDetector(options),
        new CovertChannelDetector(options),
        new EntropyCovertChannelDetector(),
        new MemoryCorruptionDetector(options),
        new UnauthorizedAccessDetector(options),
        new ShadowServerDetector(options),
        new InformationFlowDetector(options),
        new PhantomCitationSecurityDetector(options),
        new GovernanceGapDetector(options),
        new SupplyChainPoisoningDetector(options),
        new AdversarialUnicodeDetector(),
        new CodeInjectionDetector(options),
        new LanguageSwitchAttackDetector(options),
        new OutputSchemaDetector(options),
        new PiiLeakageDetector(),
        new PromptTemplateLeakageDetector(options),
        new RefusalBypassDetector(options),
        new SystemPromptLeakageDetector(options),
        new ToolDescriptionDivergenceDetector(),
        new ToolCallFrequencyDetector(),
        new ExcessiveAgencyDetector(options),
        new HumanTrustManipulationDetector(options),
        new ShorthandEmergenceDetector(options),
        new VectorRetrievalPoisoningDetector(options),
        // Hallucination (9)
        new PhantomCitationDetector(options),
        new SelfConsistencyDetector(options),
        new SourceGroundingDetector(options),
        new ConfidenceDecayDetector(options),
        new CrossAgentContradictionDetector(options),
        new GroundlessStatisticDetector(options),
        new IntraSessionContradictionDetector(options),
        new StaleKnowledgeDetector(options),
        new UncertaintyPropagationDetector(options),
        // Operational (15)
        new BlankResponseDetector(),
        new RepetitionLoopDetector(),
        new ContextCollapseDetector(options),
        new AgentProbingDetector(options),
        new QueryIntentDetector(options),
        new IncompleteCodeBlockDetector(),
        new PlaceholderTextDetector(),
        new ResponseCoherenceDetector(options),
        new PersonaDriftDetector(options),
        new SemanticRepetitionDetector(options),
        new SycophancyDetector(options),
        new WrongLanguageDetector(),
        new TruncatedOutputDetector(),
        new UnboundedConsumptionDetector(),
        new WaitingForContextDetector(options),
    ];

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
