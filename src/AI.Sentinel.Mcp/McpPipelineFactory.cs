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
    public static SentinelPipeline Create(HookConfig config, McpDetectorPreset preset)
    {
        ArgumentNullException.ThrowIfNull(config);

        var options = new SentinelOptions
        {
            OnCritical = MapDecision(config.OnCritical),
            OnHigh     = MapDecision(config.OnHigh),
            OnMedium   = MapDecision(config.OnMedium),
            OnLow      = MapDecision(config.OnLow),
        };

        var detectors = preset switch
        {
            McpDetectorPreset.All => BuildAllDetectors(options),
            _                     => BuildSecurityDetectors(),
        };

        return new SentinelPipeline(
            innerClient:        UnusedChatClient.Instance,
            pipeline:           new DetectionPipeline(detectors, escalationClient: null),
            auditStore:         new RingBufferAuditStore(capacity: 1024),
            interventionEngine: new InterventionEngine(options, mediator: null),
            options:            options);
    }

    internal static SentinelAction MapDecision(HookDecision decision) => decision switch
    {
        HookDecision.Block => SentinelAction.Quarantine,
        HookDecision.Warn  => SentinelAction.Alert,
        _                  => SentinelAction.PassThrough,
    };

    // 9 regex/pattern-based security detectors — mirrors
    // benchmarks/AI.Sentinel.Benchmarks/Harness/PipelineFactory.SecurityOnly().
    internal static IDetector[] BuildSecurityDetectors() =>
    [
        new PromptInjectionDetector(),
        new JailbreakDetector(),
        new CredentialExposureDetector(),
        new DataExfiltrationDetector(),
        new PrivilegeEscalationDetector(),
        new ToolPoisoningDetector(),
        new IndirectInjectionDetector(),
        new AgentImpersonationDetector(),
        new CovertChannelDetector(),
    ];

    // 54 detectors — mirror of what AddAISentinel registers via ZeroAllocInject
    // source-gen. Keep these in sync whenever a new detector is decorated with
    // [Singleton(As = typeof(IDetector), AllowMultiple = true)]. The drift-
    // detection test BuildAllDetectors_CountMatchesRegisteredIDetectorCount
    // fails loudly if the list here goes out of sync with the assembly.
    internal static IDetector[] BuildAllDetectors() => BuildAllDetectors(new SentinelOptions());

    internal static IDetector[] BuildAllDetectors(SentinelOptions options) =>
    [
        // Security (28)
        new PromptInjectionDetector(),
        new JailbreakDetector(),
        new CredentialExposureDetector(),
        new DataExfiltrationDetector(),
        new PrivilegeEscalationDetector(),
        new ToolPoisoningDetector(),
        new IndirectInjectionDetector(),
        new AgentImpersonationDetector(),
        new CovertChannelDetector(),
        new EntropyCovertChannelDetector(),
        new MemoryCorruptionDetector(),
        new UnauthorizedAccessDetector(),
        new ShadowServerDetector(),
        new InformationFlowDetector(),
        new PhantomCitationSecurityDetector(),
        new GovernanceGapDetector(),
        new SupplyChainPoisoningDetector(),
        new AdversarialUnicodeDetector(),
        new CodeInjectionDetector(),
        new LanguageSwitchAttackDetector(),
        new OutputSchemaDetector(options),
        new PiiLeakageDetector(),
        new PromptTemplateLeakageDetector(),
        new RefusalBypassDetector(),
        new SystemPromptLeakageDetector(),
        new ToolDescriptionDivergenceDetector(),
        new ToolCallFrequencyDetector(),
        new ExcessiveAgencyDetector(),
        new HumanTrustManipulationDetector(),
        new ShorthandEmergenceDetector(),
        // Hallucination (9)
        new PhantomCitationDetector(),
        new SelfConsistencyDetector(),
        new SourceGroundingDetector(),
        new ConfidenceDecayDetector(),
        new CrossAgentContradictionDetector(),
        new GroundlessStatisticDetector(),
        new IntraSessionContradictionDetector(),
        new StaleKnowledgeDetector(),
        new UncertaintyPropagationDetector(),
        // Operational (15)
        new BlankResponseDetector(),
        new RepetitionLoopDetector(),
        new ContextCollapseDetector(),
        new AgentProbingDetector(),
        new QueryIntentDetector(),
        new IncompleteCodeBlockDetector(),
        new PlaceholderTextDetector(),
        new ResponseCoherenceDetector(),
        new PersonaDriftDetector(),
        new SemanticRepetitionDetector(),
        new SycophancyDetector(),
        new WrongLanguageDetector(),
        new TruncatedOutputDetector(),
        new UnboundedConsumptionDetector(),
        new WaitingForContextDetector(),
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
