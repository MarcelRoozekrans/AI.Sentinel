using Microsoft.Extensions.AI;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using AI.Sentinel.Intervention;
using AI.Sentinel.Detectors.Security;
using AI.Sentinel.Detectors.Hallucination;
using AI.Sentinel.Detectors.Operational;

namespace AI.Sentinel;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddAISentinel(
        this IServiceCollection services,
        Action<SentinelOptions>? configure = null)
    {
        var opts = new SentinelOptions();
        configure?.Invoke(opts);
        services.AddSingleton(opts);
        services.AddSingleton<IAuditStore>(new RingBufferAuditStore(opts.AuditCapacity));
        services.AddSingleton(sp => new InterventionEngine(
            opts,
            mediator: sp.GetService<IMediator>(),
            logger: sp.GetService<ILogger<InterventionEngine>>()));

        RegisterDetectors(services);

        services.AddSingleton(sp =>
            new DetectionPipeline(sp.GetServices<IDetector>(), opts.EscalationClient, sp.GetService<ILogger<DetectionPipeline>>()));

        return services;
    }

    private static void RegisterDetectors(IServiceCollection services)
    {
        RegisterSecurityDetectors(services);
        RegisterHallucinationDetectors(services);
        RegisterOperationalDetectors(services);
    }

    private static void RegisterSecurityDetectors(IServiceCollection services)
    {
        services.AddSingleton<IDetector, PromptInjectionDetector>();
        services.AddSingleton<IDetector, CredentialExposureDetector>();
        services.AddSingleton<IDetector, ToolPoisoningDetector>();
        services.AddSingleton<IDetector, DataExfiltrationDetector>();
        services.AddSingleton<IDetector, JailbreakDetector>();
        services.AddSingleton<IDetector, PrivilegeEscalationDetector>();
        services.AddSingleton<IDetector, CovertChannelDetector>();
        services.AddSingleton<IDetector, EntropyCovertChannelDetector>();
        services.AddSingleton<IDetector, IndirectInjectionDetector>();
        services.AddSingleton<IDetector, AgentImpersonationDetector>();
        services.AddSingleton<IDetector, MemoryCorruptionDetector>();
        services.AddSingleton<IDetector, UnauthorizedAccessDetector>();
        services.AddSingleton<IDetector, ShadowServerDetector>();
        services.AddSingleton<IDetector, InformationFlowDetector>();
        services.AddSingleton<IDetector, PhantomCitationSecurityDetector>();
        services.AddSingleton<IDetector, GovernanceGapDetector>();
        services.AddSingleton<IDetector, SupplyChainPoisoningDetector>();
        services.AddSingleton<IDetector, PiiLeakageDetector>();
        services.AddSingleton<IDetector, AdversarialUnicodeDetector>();
        services.AddSingleton<IDetector, CodeInjectionDetector>();
        services.AddSingleton<IDetector, PromptTemplateLeakageDetector>();
        services.AddSingleton<IDetector, LanguageSwitchAttackDetector>();
        services.AddSingleton<IDetector, RefusalBypassDetector>();
    }

    private static void RegisterHallucinationDetectors(IServiceCollection services)
    {
        services.AddSingleton<IDetector, PhantomCitationDetector>();
        services.AddSingleton<IDetector, SelfConsistencyDetector>();
        services.AddSingleton<IDetector, CrossAgentContradictionDetector>();
        services.AddSingleton<IDetector, SourceGroundingDetector>();
        services.AddSingleton<IDetector, ConfidenceDecayDetector>();
        services.AddSingleton<IDetector, StaleKnowledgeDetector>();
        services.AddSingleton<IDetector, IntraSessionContradictionDetector>();
        services.AddSingleton<IDetector, GroundlessStatisticDetector>();
    }

    private static void RegisterOperationalDetectors(IServiceCollection services)
    {
        services.AddSingleton<IDetector, BlankResponseDetector>();
        services.AddSingleton<IDetector, RepetitionLoopDetector>();
        services.AddSingleton<IDetector, IncompleteCodeBlockDetector>();
        services.AddSingleton<IDetector, PlaceholderTextDetector>();
        services.AddSingleton<IDetector, ContextCollapseDetector>();
        services.AddSingleton<IDetector, AgentProbingDetector>();
        services.AddSingleton<IDetector, QueryIntentDetector>();
        services.AddSingleton<IDetector, ResponseCoherenceDetector>();
        services.AddSingleton<IDetector, SemanticRepetitionDetector>();
        services.AddSingleton<IDetector, PersonaDriftDetector>();
        services.AddSingleton<IDetector, SycophancyDetector>();
        services.AddSingleton<IDetector, WrongLanguageDetector>();
    }

    public static ChatClientBuilder UseAISentinel(this ChatClientBuilder builder) =>
        builder.Use((inner, sp) => new SentinelChatClient(
            inner,
            sp.GetRequiredService<DetectionPipeline>(),
            sp.GetRequiredService<IAuditStore>(),
            sp.GetRequiredService<InterventionEngine>(),
            sp.GetRequiredService<SentinelOptions>()));
}
