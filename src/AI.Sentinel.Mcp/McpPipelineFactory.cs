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

        var detectors = preset switch
        {
            McpDetectorPreset.All => BuildAllDetectors(),
            _                     => BuildSecurityDetectors(),
        };

        var options = new SentinelOptions
        {
            OnCritical = MapDecision(config.OnCritical),
            OnHigh     = MapDecision(config.OnHigh),
            OnMedium   = MapDecision(config.OnMedium),
            OnLow      = MapDecision(config.OnLow),
        };

        return new SentinelPipeline(
            innerClient:        UnusedChatClient.Instance,
            pipeline:           new DetectionPipeline(detectors, escalationClient: null),
            auditStore:         new RingBufferAuditStore(capacity: 1024),
            interventionEngine: new InterventionEngine(options, mediator: null),
            options:            options);
    }

    private static SentinelAction MapDecision(HookDecision decision) => decision switch
    {
        HookDecision.Block => SentinelAction.Quarantine,
        HookDecision.Warn  => SentinelAction.Alert,
        _                  => SentinelAction.PassThrough,
    };

    // 9 regex/pattern-based security detectors — mirrors
    // benchmarks/AI.Sentinel.Benchmarks/Harness/PipelineFactory.SecurityOnly().
    private static IDetector[] BuildSecurityDetectors() =>
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

    // Full set. Mirror of what AddAISentinel registers — keep these in sync
    // whenever src/AI.Sentinel/ServiceCollectionExtensions.cs gains a detector.
    private static IDetector[] BuildAllDetectors() =>
    [
        // Security
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
        // Hallucination
        new PhantomCitationDetector(),
        new SelfConsistencyDetector(),
        new SourceGroundingDetector(),
        new ConfidenceDecayDetector(),
        new CrossAgentContradictionDetector(),
        // Operational
        new BlankResponseDetector(),
        new RepetitionLoopDetector(),
        new ContextCollapseDetector(),
        new AgentProbingDetector(),
        new QueryIntentDetector(),
        new IncompleteCodeBlockDetector(),
        new PlaceholderTextDetector(),
        new ResponseCoherenceDetector(),
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
