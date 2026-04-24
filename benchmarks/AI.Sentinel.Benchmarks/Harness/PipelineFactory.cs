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
    /// Security-only pipeline with the 13 regex/pattern-based security detectors.
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
                new ToolCallFrequencyDetector(),       // SEC-19
                new ExcessiveAgencyDetector(),          // SEC-21
                new HumanTrustManipulationDetector(),   // SEC-22
                new ShorthandEmergenceDetector(),       // SEC-30
            ],
            escalationClient: null);

    /// <summary>
    /// Full pipeline with all available detectors across Security, Hallucination,
    /// and Operational categories.
    /// </summary>
    public static DetectionPipeline All() =>
        new(
            [
                // Security (22 detectors)
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
                new ToolDescriptionDivergenceDetector(), // SEC-18
                new ToolCallFrequencyDetector(),         // SEC-19
                new ExcessiveAgencyDetector(),           // SEC-21
                new HumanTrustManipulationDetector(),    // SEC-22
                new ShorthandEmergenceDetector(),        // SEC-30

                // Hallucination (6 detectors)
                new PhantomCitationDetector(),
                new SelfConsistencyDetector(),
                new SourceGroundingDetector(),
                new ConfidenceDecayDetector(),
                new CrossAgentContradictionDetector(),
                new UncertaintyPropagationDetector(),    // HAL-09

                // Operational (11 detectors)
                new BlankResponseDetector(),
                new RepetitionLoopDetector(),
                new ContextCollapseDetector(),
                new AgentProbingDetector(),
                new QueryIntentDetector(),
                new IncompleteCodeBlockDetector(),
                new PlaceholderTextDetector(),
                new ResponseCoherenceDetector(),
                new TruncatedOutputDetector(),           // OPS-09
                new WaitingForContextDetector(),         // OPS-10
                new UnboundedConsumptionDetector(),      // OPS-11
            ],
            escalationClient: null);
}
