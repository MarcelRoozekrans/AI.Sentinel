using System.Diagnostics.CodeAnalysis;
using AI.Sentinel.Detectors.Hallucination;
using AI.Sentinel.Detectors.Operational;
using AI.Sentinel.Detectors.Security;

namespace AI.Sentinel.Detection;

/// <summary>Static lookup of the official detectors by type name and by <c>DetectorId</c> value.
/// Uses <c>typeof</c> literals only, so it is safe under trimming and Native AOT. Drift against the
/// <c>[Singleton(As = typeof(IDetector))]</c> set is caught by <c>SentinelOptionsDisableDetectorTests</c>.</summary>
internal static class OfficialDetectors
{
    private static readonly (string Id, Type Type)[] Table =
    [
        ("HAL-05", typeof(ConfidenceDecayDetector)),
        ("HAL-03", typeof(CrossAgentContradictionDetector)),
        ("HAL-08", typeof(GroundlessStatisticDetector)),
        ("HAL-07", typeof(IntraSessionContradictionDetector)),
        ("HAL-01", typeof(PhantomCitationDetector)),
        ("HAL-02", typeof(SelfConsistencyDetector)),
        ("HAL-04", typeof(SourceGroundingDetector)),
        ("HAL-06", typeof(StaleKnowledgeDetector)),
        ("HAL-09", typeof(UncertaintyPropagationDetector)),
        ("OPS-06", typeof(AgentProbingDetector)),
        ("OPS-01", typeof(BlankResponseDetector)),
        ("OPS-05", typeof(ContextCollapseDetector)),
        ("OPS-03", typeof(IncompleteCodeBlockDetector)),
        ("OPS-13", typeof(PersonaDriftDetector)),
        ("OPS-04", typeof(PlaceholderTextDetector)),
        ("OPS-07", typeof(QueryIntentDetector)),
        ("OPS-02", typeof(RepetitionLoopDetector)),
        ("OPS-08", typeof(ResponseCoherenceDetector)),
        ("OPS-12", typeof(SemanticRepetitionDetector)),
        ("OPS-14", typeof(SycophancyDetector)),
        ("OPS-09", typeof(TruncatedOutputDetector)),
        ("OPS-11", typeof(UnboundedConsumptionDetector)),
        ("OPS-10", typeof(WaitingForContextDetector)),
        ("OPS-15", typeof(WrongLanguageDetector)),
        ("SEC-24", typeof(AdversarialUnicodeDetector)),
        ("SEC-10", typeof(AgentImpersonationDetector)),
        ("SEC-25", typeof(CodeInjectionDetector)),
        ("SEC-07", typeof(CovertChannelDetector)),
        ("SEC-02", typeof(CredentialExposureDetector)),
        ("SEC-04", typeof(DataExfiltrationDetector)),
        ("SEC-08", typeof(EntropyCovertChannelDetector)),
        ("SEC-21", typeof(ExcessiveAgencyDetector)),
        ("SEC-16", typeof(GovernanceGapDetector)),
        ("SEC-22", typeof(HumanTrustManipulationDetector)),
        ("SEC-09", typeof(IndirectInjectionDetector)),
        ("SEC-14", typeof(InformationFlowDetector)),
        ("SEC-05", typeof(JailbreakDetector)),
        ("SEC-27", typeof(LanguageSwitchAttackDetector)),
        ("SEC-11", typeof(MemoryCorruptionDetector)),
        ("SEC-29", typeof(OutputSchemaDetector)),
        ("SEC-15", typeof(PhantomCitationSecurityDetector)),
        ("SEC-23", typeof(PiiLeakageDetector)),
        ("SEC-06", typeof(PrivilegeEscalationDetector)),
        ("SEC-01", typeof(PromptInjectionDetector)),
        ("SEC-26", typeof(PromptTemplateLeakageDetector)),
        ("SEC-28", typeof(RefusalBypassDetector)),
        ("SEC-13", typeof(ShadowServerDetector)),
        ("SEC-30", typeof(ShorthandEmergenceDetector)),
        ("SEC-17", typeof(SupplyChainPoisoningDetector)),
        ("SEC-32", typeof(SystemPromptEchoDetector)),
        ("SEC-20", typeof(SystemPromptLeakageDetector)),
        ("SEC-19", typeof(ToolCallFrequencyDetector)),
        ("SEC-18", typeof(ToolDescriptionDivergenceDetector)),
        ("SEC-03", typeof(ToolPoisoningDetector)),
        ("SEC-12", typeof(UnauthorizedAccessDetector)),
        ("SEC-31", typeof(VectorRetrievalPoisoningDetector)),
    ];

    private static readonly Dictionary<string, Type> Lookup = Build();

    internal static int Count => Table.Length;

    internal static bool TryResolve(string nameOrId, [NotNullWhen(true)] out Type? detectorType)
    {
        if (nameOrId is not null && Lookup.TryGetValue(nameOrId, out var found))
        {
            detectorType = found;
            return true;
        }
        detectorType = null;
        return false;
    }

    private static Dictionary<string, Type> Build()
    {
        var map = new Dictionary<string, Type>(Table.Length * 2, StringComparer.Ordinal);
        foreach (var (id, type) in Table)
        {
            map.Add(type.Name, type);
            map.Add(id, type);
        }
        return map;
    }
}
