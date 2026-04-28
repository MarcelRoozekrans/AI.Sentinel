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

    /// <summary>Registers a named AI.Sentinel pipeline with isolated <see cref="SentinelOptions"/>,
    /// <see cref="IDetectionPipeline"/>, and <see cref="InterventionEngine"/>. Audit store, forwarders,
    /// and alert sink are shared with the default pipeline (and other named pipelines).
    /// Resolve via <see cref="UseAISentinel(ChatClientBuilder, string)"/>.</summary>
    /// <exception cref="ArgumentNullException">name is null.</exception>
    /// <exception cref="ArgumentException">name is empty or whitespace.</exception>
    /// <exception cref="InvalidOperationException">A pipeline with this name is already registered.</exception>
    public static IServiceCollection AddAISentinel(
        this IServiceCollection services,
        string name,
        Action<SentinelOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(name);
        ArgumentNullException.ThrowIfNull(configure);
        if (string.IsNullOrWhiteSpace(name))
        {
            throw new ArgumentException("AI.Sentinel pipeline name must not be empty or whitespace.", nameof(name));
        }

        if (services.Any(d => d.IsKeyedService && d.ServiceKey is string k
            && string.Equals(k, name, StringComparison.Ordinal)
            && d.ServiceType == typeof(SentinelOptions)))
        {
            throw new InvalidOperationException($"AI.Sentinel pipeline '{name}' is already registered.");
        }

        return RegisterPipeline(services, name, configure);
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
            // Named pipeline — keyed singletons for SentinelOptions, IDetectionPipeline, InterventionEngine.
            // Audit/forwarder/alert/detector-pool/IToolCallGuard stay shared across all pipelines (registered
            // by the default unnamed AddAISentinel call, or absent if the user only registered named pipelines).
            services.AddKeyedSingleton(name, opts);
            services.AddKeyedSingleton(name, (sp, _) => BuildInterventionEngine(opts, sp));

            // Detectors registered globally — official via source-gen (idempotent), user detectors via
            // RegisterUserDetectors (adds to the global IDetector pool). User-added detectors from any
            // named pipeline are visible to ALL pipelines; per-name customization rides on Configure<T>.
            services.AddAISentinelDetectors();
            RegisterUserDetectors(services, opts);

            services.AddKeyedSingleton<IDetectionPipeline>(name, (sp, _) => BuildDetectionPipeline(opts, sp));
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

    /// <summary>Resolves a named AI.Sentinel pipeline previously registered via
    /// <see cref="AddAISentinel(IServiceCollection, string, Action{SentinelOptions})"/>.
    /// Throws <see cref="InvalidOperationException"/> at chat client construction time if
    /// no pipeline with this name was registered.</summary>
    public static ChatClientBuilder UseAISentinel(this ChatClientBuilder builder, string name) =>
        builder.Use((inner, sp) =>
        {
            ArgumentNullException.ThrowIfNull(name);

            var opts = sp.GetRequiredKeyedService<SentinelOptions>(name);
            var pipeline = sp.GetRequiredKeyedService<IDetectionPipeline>(name);
            var engine = sp.GetRequiredKeyedService<InterventionEngine>(name);

            // Shared infrastructure (audit store, alert sink, forwarders) is registered ONLY
            // by the default unnamed AddAISentinel(...) call. Surface a clearer error than
            // "No service for type 'IAuditStore' has been registered" if the user skipped it.
            if (sp.GetService<IAuditStore>() is null)
            {
                throw new InvalidOperationException(
                    $"AI.Sentinel pipeline '{name}': shared infrastructure (IAuditStore) is missing. Call services.AddAISentinel(...) once before registering or resolving named pipelines — the default unnamed call wires the shared audit store, forwarders, and alert sink.");
            }

            if (opts.EmbeddingGenerator is null)
            {
                var logger = sp.GetService<ILogger<SentinelPipeline>>();
                var semanticCount = sp.GetServices<IDetector>().Count(d => d is SemanticDetectorBase);
                logger?.LogWarning(
                    "AI.Sentinel pipeline '{Name}': EmbeddingGenerator is not configured. All {Count} semantic detectors will return Clean until an IEmbeddingGenerator is provided.",
                    name, semanticCount);
            }

            return new SentinelChatClient(
                inner,
                pipeline,
                sp.GetRequiredService<IAuditStore>(),     // shared
                engine,
                opts,
                sp.GetRequiredService<IAlertSink>(),      // shared
                sp.GetServices<IAuditForwarder>());       // shared
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
