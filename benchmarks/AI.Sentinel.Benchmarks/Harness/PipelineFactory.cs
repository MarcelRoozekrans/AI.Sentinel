using AI.Sentinel.Detection;
using AI.Sentinel.Detectors.Hallucination;
using AI.Sentinel.Detectors.Operational;
using AI.Sentinel.Detectors.Security;

namespace AI.Sentinel.Benchmarks.Harness;

/// <summary>
/// Builds <see cref="DetectionPipeline"/> instances for benchmark presets.
/// Created fresh per benchmark run (not shared as statics) so each run starts
/// with clean detector state.
/// </summary>
internal static class PipelineFactory
{
    /// <summary>Empty pipeline — measures pure pipeline overhead with no detectors.</summary>
    public static DetectionPipeline Empty() =>
        new([], escalationClient: null);

    /// <summary>
    /// Security-only pipeline with the 9 core fast-regex security detectors.
    /// </summary>
    public static DetectionPipeline SecurityOnly() =>
        new(
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
            ],
            escalationClient: null);

    /// <summary>
    /// Full pipeline with all available detectors across Security, Hallucination,
    /// and Operational categories.
    /// </summary>
    public static DetectionPipeline All() =>
        new(
            [
                // Security (17 detectors)
                new PromptInjectionDetector(),
                new CredentialExposureDetector(),
                new ToolPoisoningDetector(),
                new DataExfiltrationDetector(),
                new EntropyCovertChannelDetector(),
                new MemoryCorruptionDetector(),
                new UnauthorizedAccessDetector(),
                new ShadowServerDetector(),
                new InformationFlowDetector(),
                new PhantomCitationSecurityDetector(),
                new GovernanceGapDetector(),
                new CovertChannelDetector(),
                new JailbreakDetector(),
                new IndirectInjectionDetector(),
                new AgentImpersonationDetector(),
                new PrivilegeEscalationDetector(),
                new SupplyChainPoisoningDetector(),

                // Hallucination (5 detectors)
                new PhantomCitationDetector(),
                new SelfConsistencyDetector(),
                new SourceGroundingDetector(),
                new ConfidenceDecayDetector(),
                new CrossAgentContradictionDetector(),

                // Operational (8 detectors)
                new BlankResponseDetector(),
                new RepetitionLoopDetector(),
                new ContextCollapseDetector(),
                new AgentProbingDetector(),
                new QueryIntentDetector(),
                new IncompleteCodeBlockDetector(),
                new PlaceholderTextDetector(),
                new ResponseCoherenceDetector(),
            ],
            escalationClient: null);
}
