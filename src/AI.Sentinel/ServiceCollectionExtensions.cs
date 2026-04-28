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
        return RegisterPipeline(services, name: null, configure);
    }

    private static IServiceCollection RegisterPipeline(
        IServiceCollection services,
        string? name,
        Action<SentinelOptions>? configure)
    {
        var opts = new SentinelOptions();
        configure?.Invoke(opts);

        if (name is null)
        {
            // Default (unnamed) pipeline — unkeyed singletons, full v1.0 backward compat
            services.AddSingleton(opts);
            services.AddSingleton<IAlertSink>(_ => BuildAlertSink(opts));
            services.AddSingleton<IAuditStore>(BuildAuditStore(opts));
            services.AddSingleton(sp => BuildInterventionEngine(opts, sp));
            services.AddAISentinelDetectors();
            RegisterUserDetectors(services, opts);
            services.AddSingleton<IDetectionPipeline>(sp => BuildDetectionPipeline(opts, sp));
            services.AddSingleton<IToolCallGuard>(sp => BuildToolCallGuard(services, opts, sp));
        }
        else
        {
            // Named pipeline — Task 2 fills this branch
#pragma warning disable MA0025 // Placeholder for Task 2
            throw new NotImplementedException("Named pipelines arrive in Task 2.");
#pragma warning restore MA0025
        }

        return services;
    }

    private static IAlertSink BuildAlertSink(SentinelOptions opts)
    {
        IAlertSink raw = opts.AlertWebhook is not null
            ? new WebhookAlertSink(opts.AlertWebhook)
            : NullAlertSink.Instance;
        return new DeduplicatingAlertSink(
            new AlertSinkInstrumented(raw),
            opts.AlertDeduplicationWindow,
            opts.SessionIdleTimeout);
    }

    private static IAuditStore BuildAuditStore(SentinelOptions opts)
        => new AuditStoreInstrumented(new RingBufferAuditStore(opts.AuditCapacity));

    private static InterventionEngine BuildInterventionEngine(SentinelOptions opts, IServiceProvider sp)
        => new(opts, mediator: sp.GetService<IMediator>(), logger: sp.GetService<ILogger<InterventionEngine>>());

    private static IDetectionPipeline BuildDetectionPipeline(SentinelOptions opts, IServiceProvider sp)
        => new DetectionPipelineInstrumented(
            new DetectionPipeline(
                sp.GetServices<IDetector>(),
                opts.GetDetectorConfigurations(),
                opts.EscalationClient,
                sp.GetService<ILogger<DetectionPipeline>>()));

    private static IToolCallGuard BuildToolCallGuard(IServiceCollection services, SentinelOptions opts, IServiceProvider sp)
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
    }

    private static void RegisterUserDetectors(IServiceCollection services, SentinelOptions opts)
    {
        foreach (var reg in opts.GetDetectorRegistrations())
        {
            if (reg.Factory is null)
            {
                services.AddSingleton(typeof(IDetector), reg.DetectorType);
            }
            else
            {
                services.AddSingleton<IDetector>(sp => reg.Factory(sp));
            }
        }
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
                sp.GetRequiredService<IAlertSink>(),
                sp.GetServices<IAuditForwarder>());
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
            sp.GetRequiredService<IAlertSink>(),
            sp.GetServices<IAuditForwarder>());
    }
}
