using Microsoft.Extensions.AI;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using AI.Sentinel.Alerts;
using AI.Sentinel.Approvals;
using AI.Sentinel.Audit;
using AI.Sentinel.Authorization;
using AI.Sentinel.Detection;
using AI.Sentinel.Intervention;
using ZeroAlloc.Authorization;

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

        // Auto-register InMemoryApprovalStore if any binding has an ApprovalSpec and the user
        // hasn't registered an IApprovalStore yet. Keeps the happy path zero-config.
        if (opts.GetAuthorizationBindings().Any(b => b.ApprovalSpec is not null) &&
            !services.Any(d => d.ServiceType == typeof(IApprovalStore)))
        {
            services.AddSingleton<IApprovalStore, InMemoryApprovalStore>();
        }

        if (name is null)
        {
            // Default (unnamed) pipeline — unkeyed singletons, full v1.0 backward compat
            services.AddSingleton(opts);
            services.AddSingleton<IAlertSink>(_ => BuildAlertSink(opts));
            services.AddSingleton<IAuditStore>(BuildAuditStore(opts));
            services.AddSingleton(sp => BuildInterventionEngine(opts, sp));
            AddOfficialDetectorsOnce(services);
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

            // Detectors registered globally — the official set exactly once (see AddOfficialDetectorsOnce),
            // user detectors via RegisterUserDetectors (adds to the global IDetector pool). User-added
            // detectors from any named pipeline are visible to ALL pipelines; per-name customization
            // rides on Configure<T>.
            AddOfficialDetectorsOnce(services);
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
                sp.GetService<ILogger<DetectionPipeline>>(),
                opts.OnDetectorFailure));

    private static IToolCallGuard BuildToolCallGuard(IServiceCollection services, SentinelOptions opts, IServiceProvider sp)
    {
        // Re-check at factory time (not at AddAISentinel time) so users can add ISecurityContext after AddAISentinel.
        var hasSecurityContext = services.Any(d => d.ServiceType == typeof(ISecurityContext));

        var policyByName = new Dictionary<string, IAuthorizationPolicy>(StringComparer.Ordinal);
        foreach (var p in sp.GetServices<IAuthorizationPolicy>())
        {
            var attrs = p.GetType().GetCustomAttributes(typeof(PolicyAttribute), inherit: false);
            if (attrs.Length == 0) continue;
            var attr = (PolicyAttribute)attrs[0];
            policyByName[attr.Name] = p;
        }

        var bindings = opts.GetAuthorizationBindings();
        var logger = sp.GetService<ILogger<DefaultToolCallGuard>>();
        var pipelineLogger = sp.GetService<ILogger<SentinelPipeline>>();

        EmitAuthorizationStartupWarnings(opts, bindings, policyByName, hasSecurityContext, pipelineLogger);

        var approvalStore = sp.GetService<IApprovalStore>();
        return new DefaultToolCallGuard(bindings, policyByName, opts.DefaultToolPolicy, approvalStore, logger);
    }

    /// <summary>Presence of this marker proves the official detector set is already in the container.</summary>
    private sealed class OfficialDetectorsRegistered;

    /// <summary>Registers the source-generated official detector set exactly once per <see cref="IServiceCollection"/>.
    /// The generated <c>AddAISentinelDetectors</c> is not idempotent — every detector is annotated
    /// <c>[Singleton(As = typeof(IDetector), AllowMultiple = true)]</c>, which opts out of ZeroAlloc.Inject's
    /// TryAdd-by-default, so each call appends another full set. Without this guard the README's
    /// named-pipeline example (default + "strict" + "lenient") built a pipeline holding three copies of
    /// the set, running every detector three times per scan and reporting each finding three times.</summary>
    private static void AddOfficialDetectorsOnce(IServiceCollection services)
    {
        if (services.Any(d => d.ServiceType == typeof(OfficialDetectorsRegistered)))
        {
            return;
        }

        services.AddSingleton(new OfficialDetectorsRegistered());
        services.AddAISentinelDetectors();
    }

    private static void RegisterUserDetectors(IServiceCollection services, SentinelOptions opts)
    {
        foreach (var reg in opts.GetDetectorRegistrations())
        {
            if (reg.Factory is null)
            {
                // A type-based registration carries no per-instance state, and Configure<T> is keyed by
                // type, so a repeat of the same type is always redundant. This happens for real via the
                // shared base-config recipe in the README's "Named pipelines" section: one
                // Action<SentinelOptions> containing AddDetector<T>(), applied to the default pipeline
                // and to each named one. Factory registrations are left alone — two factories may
                // legitimately produce differently-constructed instances of the same type.
                services.TryAddEnumerable(ServiceDescriptor.Singleton(typeof(IDetector), reg.DetectorType));
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
            WarnIfSemanticDetectionInert(sp, opts, pipelineName: null);
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
            // We probe IAuditStore as the canary — if it's missing, the alert sink and
            // forwarders are almost certainly missing too.
            if (sp.GetService<IAuditStore>() is null)
            {
                throw new InvalidOperationException(
                    $"AI.Sentinel pipeline '{name}': shared infrastructure (IAuditStore, IAlertSink, IAuditForwarder) is missing. Call services.AddAISentinel(...) once before registering or resolving named pipelines — the default unnamed call wires the shared audit store, forwarders, and alert sink.");
            }

            WarnIfSemanticDetectionInert(sp, opts, pipelineName: name);

            return new SentinelChatClient(
                inner,
                pipeline,
                sp.GetRequiredService<IAuditStore>(),     // shared
                engine,
                opts,
                sp.GetRequiredService<IAlertSink>(),      // shared
                sp.GetServices<IAuditForwarder>());       // shared
        });

    /// <summary>Builds the "semantic detection is inert" warning, or <see langword="null"/> when it is active.</summary>
    private static string? InertSemanticWarning(SentinelOptions? opts, IServiceProvider sp, string? pipelineName)
    {
        if (opts is null || opts.EmbeddingGenerator is not null)
        {
            return null;
        }

        var count = sp.GetServices<IDetector>().Count(d => d is SemanticDetectorBase);
        if (count == 0)
        {
            return null;
        }

        return InertSemanticMessage(count, pipelineName);
    }

    private static string InertSemanticMessage(int count, string? pipelineName)
    {
        var scope = pipelineName is null ? "AI.Sentinel" : $"AI.Sentinel pipeline '{pipelineName}'";
        return $"{scope}: EmbeddingGenerator is not configured — all {count} semantic detectors, including SEC-01 PromptInjection and SEC-05 Jailbreak, return Clean on every scan. Configure SentinelOptions.EmbeddingGenerator to enable semantic detection — the bundled CLI tools cannot supply one.";
    }

    private static void WarnIfSemanticDetectionInert(IServiceProvider sp, SentinelOptions? opts, string? pipelineName)
    {
        if (InertSemanticWarning(opts, sp, pipelineName) is not { } warning)
        {
            return;
        }

        sp.GetService<ILogger<SentinelPipeline>>()?.LogWarning("{SentinelWarning}", warning);
    }

    /// <summary>Returns a warning when semantic detection cannot fire, or <see langword="null"/> when it is
    /// active. Hosts with an <see cref="ILogger"/> get this logged automatically when the pipeline is built;
    /// hosts without one — the CLI tools register no logging provider — call this and write the result
    /// to stderr. Without it an inert SEC-01 is indistinguishable from "no threat found" (#170).</summary>
    public static string? DescribeInertSemanticDetection(this IServiceProvider sp)
    {
        ArgumentNullException.ThrowIfNull(sp);
        return InertSemanticWarning(sp.GetService<SentinelOptions>(), sp, pipelineName: null);
    }

    /// <summary>As <see cref="DescribeInertSemanticDetection(IServiceProvider)"/>, for hosts that compose
    /// their detector set by hand instead of through DI — the MCP proxy builds its own preset list.</summary>
    public static string? DescribeInertSemanticDetection(SentinelOptions options, IEnumerable<IDetector> detectors)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(detectors);
        if (options.EmbeddingGenerator is not null)
        {
            return null;
        }

        var count = detectors.Count(d => d is SemanticDetectorBase);
        return count == 0 ? null : InertSemanticMessage(count, pipelineName: null);
    }

    public static SentinelPipeline BuildSentinelPipeline(
        this IServiceProvider sp,
        IChatClient innerClient)
    {
        ArgumentNullException.ThrowIfNull(innerClient);
        WarnIfSemanticDetectionInert(sp, sp.GetService<SentinelOptions>(), pipelineName: null);
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
