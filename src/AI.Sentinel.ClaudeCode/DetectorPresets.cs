using AI.Sentinel.Detection;
using AI.Sentinel.Detectors.Compliance;
using AI.Sentinel.Detectors.Hallucination;
using AI.Sentinel.Detectors.Operational;
using AI.Sentinel.Detectors.Security;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace AI.Sentinel.ClaudeCode;

/// <summary>The detector sets behind <see cref="DetectorPreset"/>, shared by the hook CLIs and the MCP proxy.</summary>
internal static class DetectorPresets
{
    /// <summary>Reads a preset setting: <c>all</c>, in any case, selects <see cref="DetectorPreset.All"/>; anything
    /// else, or no value, keeps the <see cref="DetectorPreset.Security"/> default.</summary>
    internal static DetectorPreset Parse(string? value) =>
        string.Equals(value, "all", StringComparison.OrdinalIgnoreCase) ? DetectorPreset.All : DetectorPreset.Security;

    /// <summary>The detectors <paramref name="preset"/> stands for, built with <paramref name="options"/>.</summary>
    internal static IDetector[] Build(DetectorPreset preset, SentinelOptions options) => preset switch
    {
        DetectorPreset.All => BuildAll(options),
        _ => BuildSecurity(options),
    };

    /// <summary>
    /// Narrows the detectors <c>AddAISentinel</c> registered in <paramref name="services"/> to
    /// <paramref name="preset"/>. <see cref="DetectorPreset.All"/> keeps them all; any other preset replaces every
    /// <see cref="IDetector"/> registration with its own detectors, built with the <see cref="SentinelOptions"/> the
    /// default <c>AddAISentinel</c> call registered. That includes detectors added with
    /// <see cref="SentinelOptions.AddDetector{T}"/>, which <c>AddAISentinel</c> registers itself, so call it only for
    /// a pipeline that adds none.
    /// </summary>
    /// <exception cref="InvalidOperationException">The default <c>AddAISentinel</c> has not been called.</exception>
    internal static IServiceCollection UseDetectorPreset(this IServiceCollection services, DetectorPreset preset)
    {
        ArgumentNullException.ThrowIfNull(services);
        if (preset == DetectorPreset.All)
            return services;

        var options = services.LastOrDefault(d => d.ServiceType == typeof(SentinelOptions) && !d.IsKeyedService)
            ?.ImplementationInstance as SentinelOptions
            ?? throw new InvalidOperationException("Call AddAISentinel before UseDetectorPreset.");
        services.RemoveAll<IDetector>();
        foreach (var detector in Build(preset, options))
            services.AddSingleton(detector);
        return services;
    }

    internal static IDetector[] BuildSecurity() => BuildSecurity(new SentinelOptions());

    // 14 security detectors, the set benchmarks/AI.Sentinel.Benchmarks/Harness/PipelineFactory.SecurityOnly()
    // measures, plus the 4 Art. 5 compliance detectors. SEC-23 is here because the redaction pass takes its
    // redactors from the pipeline's detectors: without it, a host that redacts by default would redact secrets only,
    // and no PII. Every preset includes CMP-01..04; they run only when the host's COMPLIANCE switch turns them on,
    // because they are off by default.
    internal static IDetector[] BuildSecurity(SentinelOptions options) =>
    [
        new PromptInjectionDetector(options),
        new JailbreakDetector(options),
        new CredentialExposureDetector(),
        new PiiLeakageDetector(),             // SEC-23
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
        .. BuildComplianceSection(options),
    ];

    // Mirror of what AddAISentinel registers via ZeroAllocInject source-gen. Keep these in sync whenever a new detector
    // is registered as an IDetector singleton. The drift-detection test BuildAll_CountMatchesRegisteredIDetectorCount
    // fails loudly if the list here goes out of sync with the assembly.
    internal static IDetector[] BuildAll() => BuildAll(new SentinelOptions());

    internal static IDetector[] BuildAll(SentinelOptions options) =>
        [.. BuildSecuritySection(options), .. BuildQualitySection(options), .. BuildComplianceSection(options)];

    /// <summary>The Art. 5 prohibited-practice detectors. Shared by both presets.</summary>
    private static IDetector[] BuildComplianceSection(SentinelOptions options) =>
    [
        // Compliance (4)
        new SocialScoringDetector(options),
        new WorkplaceEmotionRecognitionDetector(options),
        new SensitiveBiometricCategorisationDetector(options),
        new ProfilingCrimePredictionDetector(options),
    ];

    /// <summary>Split from BuildAll only to stay inside the method-length limit; the sections
    /// together must still mirror every [Singleton] detector in the assembly.</summary>
    private static IDetector[] BuildQualitySection(SentinelOptions options) =>
    [
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

    private static IDetector[] BuildSecuritySection(SentinelOptions options) =>
    [
        // Security (32)
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
        new SystemPromptEchoDetector(),
        new ToolDescriptionDivergenceDetector(),
        new ToolCallFrequencyDetector(),
        new ExcessiveAgencyDetector(options),
        new HumanTrustManipulationDetector(options),
        new ShorthandEmergenceDetector(options),
        new VectorRetrievalPoisoningDetector(options),
    ];
}
