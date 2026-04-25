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
    /// Security-only pipeline with the 13 semantic security detectors.
    /// </summary>
    public static DetectionPipeline SecurityOnly() => SecurityOnly(new SentinelOptions());

    public static DetectionPipeline SecurityOnly(SentinelOptions options) =>
        new(
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
                new ToolCallFrequencyDetector(),       // SEC-19
                new ExcessiveAgencyDetector(options),   // SEC-21
                new HumanTrustManipulationDetector(options), // SEC-22
                new ShorthandEmergenceDetector(options),     // SEC-30
            ],
            escalationClient: null);

    /// <summary>
    /// Full pipeline with all available detectors across Security, Hallucination,
    /// and Operational categories.
    /// </summary>
    public static DetectionPipeline All() => All(new SentinelOptions());

    public static DetectionPipeline All(SentinelOptions options) =>
        new(
            [
                // Security (22 detectors)
                new PromptInjectionDetector(options),
                new CredentialExposureDetector(),
                new ToolPoisoningDetector(options),
                new DataExfiltrationDetector(options),
                new EntropyCovertChannelDetector(),
                new MemoryCorruptionDetector(options),
                new UnauthorizedAccessDetector(options),
                new ShadowServerDetector(options),
                new InformationFlowDetector(options),
                new PhantomCitationSecurityDetector(options),
                new GovernanceGapDetector(options),
                new CovertChannelDetector(options),
                new JailbreakDetector(options),
                new IndirectInjectionDetector(options),
                new AgentImpersonationDetector(options),
                new PrivilegeEscalationDetector(options),
                new SupplyChainPoisoningDetector(options),
                new ToolDescriptionDivergenceDetector(), // SEC-18
                new ToolCallFrequencyDetector(),         // SEC-19
                new ExcessiveAgencyDetector(options),    // SEC-21
                new HumanTrustManipulationDetector(options), // SEC-22
                new ShorthandEmergenceDetector(options),     // SEC-30

                // Hallucination (6 detectors)
                new PhantomCitationDetector(options),
                new SelfConsistencyDetector(options),
                new SourceGroundingDetector(options),
                new ConfidenceDecayDetector(options),
                new CrossAgentContradictionDetector(options),
                new UncertaintyPropagationDetector(options),    // HAL-09

                // Operational (11 detectors)
                new BlankResponseDetector(),
                new RepetitionLoopDetector(),
                new ContextCollapseDetector(options),
                new AgentProbingDetector(options),
                new QueryIntentDetector(options),
                new IncompleteCodeBlockDetector(),
                new PlaceholderTextDetector(),
                new ResponseCoherenceDetector(options),
                new TruncatedOutputDetector(),           // OPS-09
                new WaitingForContextDetector(options),  // OPS-10
                new UnboundedConsumptionDetector(),      // OPS-11
            ],
            escalationClient: null);
}
