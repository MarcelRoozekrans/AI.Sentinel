using Microsoft.Extensions.AI;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using AI.Sentinel.Alerts;
using AI.Sentinel.Audit;
using AI.Sentinel.Authorization;
using AI.Sentinel.Detection;
using AI.Sentinel.Intervention;

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
        services.AddSingleton<IAlertSink>(_ =>
        {
            IAlertSink raw = opts.AlertWebhook is not null
                ? new WebhookAlertSink(opts.AlertWebhook)
                : NullAlertSink.Instance;
            return new DeduplicatingAlertSink(
                new AlertSinkInstrumented(raw),
                opts.AlertDeduplicationWindow,
                opts.SessionIdleTimeout);
        });
        services.AddSingleton<IAuditStore>(
            new AuditStoreInstrumented(new RingBufferAuditStore(opts.AuditCapacity)));
        services.AddSingleton(sp => new InterventionEngine(
            opts,
            mediator: sp.GetService<IMediator>(),
            logger: sp.GetService<ILogger<InterventionEngine>>()));

        services.AddAISentinelDetectors();

        services.AddSingleton<IDetectionPipeline>(sp =>
            new DetectionPipelineInstrumented(
                new DetectionPipeline(sp.GetServices<IDetector>(), opts.EscalationClient, sp.GetService<ILogger<DetectionPipeline>>())));

        services.AddSingleton<IToolCallGuard>(sp =>
        {
            // Re-check at factory time (not at AddAISentinel time) so users can add ISecurityContext after AddAISentinel.
            var hasSecurityContext = services.Any(d => d.ServiceType == typeof(ISecurityContext));

            var policyByName = new Dictionary<string, IAuthorizationPolicy>(StringComparer.Ordinal);
            foreach (var p in sp.GetServices<IAuthorizationPolicy>())
            {
                var attrs = p.GetType().GetCustomAttributes(typeof(AuthorizationPolicyAttribute), inherit: false);
                if (attrs.Length == 0) continue;
                var attr = (AuthorizationPolicyAttribute)attrs[0];
                policyByName[attr.Name] = p;
            }

            var bindings = opts.GetAuthorizationBindings();
            var logger = sp.GetService<ILogger<DefaultToolCallGuard>>();
            var pipelineLogger = sp.GetService<ILogger<SentinelPipeline>>();

            EmitAuthorizationStartupWarnings(opts, bindings, policyByName, hasSecurityContext, pipelineLogger);

            return new DefaultToolCallGuard(bindings, policyByName, opts.DefaultToolPolicy, logger);
        });

        return services;
    }

    private static void EmitAuthorizationStartupWarnings(
        SentinelOptions opts,
        IReadOnlyList<ToolCallPolicyBinding> bindings,
        IReadOnlyDictionary<string, IAuthorizationPolicy> policiesByName,
        bool hasSecurityContext,
        ILogger<SentinelPipeline>? logger)
    {
        if (logger is null) return;

        if (opts.DefaultToolPolicy == ToolPolicyDefault.Deny && policiesByName.Count == 0)
        {
            logger.LogWarning("AI.Sentinel: DefaultToolPolicy=Deny but no IAuthorizationPolicy implementations are registered — every tool call will be denied.");
        }

        foreach (var binding in bindings)
        {
            if (!policiesByName.ContainsKey(binding.PolicyName))
            {
                logger.LogError("AI.Sentinel: RequireToolPolicy(\"{Pattern}\", \"{Policy}\") references unknown policy '{Policy}'. This binding will deny every matching call.",
                    binding.Pattern, binding.PolicyName, binding.PolicyName);
            }
        }

        if (bindings.Count > 0 && !hasSecurityContext)
        {
            logger.LogWarning("AI.Sentinel: tool-call policies are configured, but no ISecurityContext provider is registered — all calls will resolve as Anonymous and policies referencing roles will deny.");
        }
    }

    public static ChatClientBuilder UseAISentinel(this ChatClientBuilder builder) =>
        builder.Use((inner, sp) =>
        {
            var opts = sp.GetRequiredService<SentinelOptions>();
            if (opts.EmbeddingGenerator is null)
            {
                var logger = sp.GetService<ILogger<SentinelPipeline>>();
                var semanticCount = sp.GetServices<IDetector>().Count(d => d is SemanticDetectorBase);
                logger?.LogWarning(
                    "SentinelOptions.EmbeddingGenerator is not configured. All {Count} semantic detectors will return Clean until an IEmbeddingGenerator is provided.",
                    semanticCount);
            }
            return new SentinelChatClient(
                inner,
                sp.GetRequiredService<IDetectionPipeline>(),
                sp.GetRequiredService<IAuditStore>(),
                sp.GetRequiredService<InterventionEngine>(),
                opts,
                sp.GetRequiredService<IAlertSink>());
        });

    public static SentinelPipeline BuildSentinelPipeline(
        this IServiceProvider sp,
        IChatClient innerClient)
    {
        ArgumentNullException.ThrowIfNull(innerClient);
        return new SentinelPipeline(
            innerClient,
            sp.GetRequiredService<IDetectionPipeline>(),
            sp.GetRequiredService<IAuditStore>(),
            sp.GetRequiredService<InterventionEngine>(),
            sp.GetRequiredService<SentinelOptions>(),
            sp.GetRequiredService<IAlertSink>());
    }
}
