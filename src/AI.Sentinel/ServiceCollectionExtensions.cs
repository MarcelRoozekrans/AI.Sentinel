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
using AI.Sentinel.Screening;
using AI.Sentinel.Transparency;
using ZeroAlloc.Authorization;

namespace AI.Sentinel;

public static class ServiceCollectionExtensions
{
    /// <summary>Registers the default (unnamed) AI.Sentinel pipeline: unkeyed <see cref="SentinelOptions"/>,
    /// <see cref="IDetectionPipeline"/>, <see cref="InterventionEngine"/>, and the shared audit store,
    /// alert sink and tool-call guard. Named pipelines added with
    /// <see cref="AddAISentinel(IServiceCollection, string, Action{SentinelOptions})"/> may come before or after it.</summary>
    /// <exception cref="InvalidOperationException">The default pipeline is already registered on this
    /// collection, which includes an unkeyed <see cref="SentinelOptions"/> registered by hand. Call this once,
    /// for example from the composition root only.</exception>
    public static IServiceCollection AddAISentinel(
        this IServiceCollection services,
        Action<SentinelOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        if (services.Any(d => !d.IsKeyedService && d.ServiceType == typeof(SentinelOptions)))
        {
            throw new InvalidOperationException("The default AI.Sentinel pipeline is already registered.");
        }

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
        RejectRedactOnSeverityOptions(opts);
        RejectRedactOnNonRedactingDetectors(opts, nameof(configure));
        RejectInvalidTransparencyOptions(opts, nameof(configure));
        RejectInvalidThresholds(opts, nameof(configure));

        // Auto-register InMemoryApprovalStore if any binding has an ApprovalSpec and the user
        // hasn't registered an IApprovalStore yet. Keeps the happy path zero-config.
        if (opts.GetAuthorizationBindings().Any(b => b.ApprovalSpec is not null) &&
            !ApprovalStoreAuditing.IsApprovalStoreRegistered(services))
        {
            services.AddSentinelApprovalStore(sp => new InMemoryApprovalStore(sp.GetService<TimeProvider>() ?? TimeProvider.System));
        }

        if (name is null)
        {
            // Default (unnamed) pipeline — unkeyed singletons, full v1.0 backward compat. The options are
            // resolved, not registered as an instance, so the embedding generator can come from the container;
            // everything below reads that resolved instance, which the detectors are built with too.
            services.AddSingleton(sp => WithEmbeddingGeneratorFromServices(opts, sp));
            services.AddSingleton(sp => new DefaultEmbeddingScope(
                EmbeddingScope.Resolve(sp.GetRequiredService<SentinelOptions>(), inherited: null)));
            services.AddSingleton<IAlertSink>(sp => BuildAlertSink(sp.GetRequiredService<SentinelOptions>()));
            services.AddSingleton<IAuditStore>(BuildAuditStore(opts));
            services.AddSingleton(sp => BuildInterventionEngine(sp.GetRequiredService<SentinelOptions>(), sp));
            AddOfficialDetectorsOnce(services);
            RegisterUserDetectors(services, opts);
            services.AddSingleton<IDetectionPipeline>(sp => BuildDetectionPipeline(
                sp.GetRequiredService<SentinelOptions>(), sp, sp.GetRequiredService<DefaultEmbeddingScope>().Scope));
            services.AddSingleton<IToolCallGuard>(sp => BuildToolCallGuard(services, sp.GetRequiredService<SentinelOptions>(), sp));
            services.AddSingleton<ISentinelScreener>(sp =>
                new SentinelScreener(() => sp.BuildSentinelPipeline(NeverCalledChatClient.Instance)));
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

            services.AddKeyedSingleton<IDetectionPipeline>(name, (sp, _) => BuildDetectionPipeline(
                opts, sp, EmbeddingScope.Resolve(opts, sp.GetService<DefaultEmbeddingScope>()?.Scope)));
            services.AddKeyedSingleton<ISentinelScreener>(name, (sp, _) =>
                new SentinelScreener(() => BuildNamedSentinelPipeline(sp, name, NeverCalledChatClient.Instance)));
        }

        return services;
    }

    /// <summary>The default pipeline's options as this provider uses them: <paramref name="opts"/> itself when it
    /// sets <see cref="SentinelOptions.EmbeddingGenerator"/>, turns
    /// <see cref="SentinelOptions.UseEmbeddingGeneratorFromServices"/> off or the container has no generator,
    /// otherwise a copy that uses the container's.</summary>
    /// <remarks>A copy, not an assignment: <paramref name="opts"/> is shared by every provider built from the same
    /// collection, so writing one provider's generator into it would hand that generator to the next provider
    /// and make it look explicitly configured there.</remarks>
    private static SentinelOptions WithEmbeddingGeneratorFromServices(SentinelOptions opts, IServiceProvider sp) =>
        opts.EmbeddingGenerator is null && opts.UseEmbeddingGeneratorFromServices
        && sp.GetService<IEmbeddingGenerator<string, Embedding<float>>>() is { } generator
            ? opts.WithEmbeddingGenerator(generator)
            : opts;

    private static void RejectInvalidTransparencyOptions(SentinelOptions opts, string paramName)
    {
        var t = opts.Transparency;
        if (t.Enabled && !Enum.IsDefined(t.NoticeMode))
        {
            throw new ArgumentException(
                "SentinelOptions.Transparency.NoticeMode is not a defined TransparencyNoticeMode value. " +
                "Use OncePerConversation, EveryReply or Never.",
                paramName);
        }
        if (t.Enabled && t.NoticeMode != TransparencyNoticeMode.Never && string.IsNullOrWhiteSpace(t.Notice))
        {
            throw new ArgumentException(
                "SentinelOptions.Transparency.Notice cannot be empty while Transparency is enabled and NoticeMode is not Never. " +
                "Set a notice text or use NoticeMode = Never.",
                paramName);
        }
    }

    private static void RejectRedactOnSeverityOptions(SentinelOptions opts)
    {
        foreach (var (option, action) in new[]
        {
            (nameof(SentinelOptions.OnCritical), opts.OnCritical),
            (nameof(SentinelOptions.OnHigh), opts.OnHigh),
            (nameof(SentinelOptions.OnMedium), opts.OnMedium),
            (nameof(SentinelOptions.OnLow), opts.OnLow),
        })
        {
            if (action == SentinelAction.Redact)
            {
                throw new ArgumentException(
                    $"SentinelOptions.{option} cannot be Redact: redaction needs the location of a match, which a severity does not have. " +
                    "Set DetectorConfiguration.Action on a redacting detector instead.",
                    option);
            }
        }
    }

    // Configure<T> keys each configuration by the detector type, so whether it can redact is known here, at
    // registration, without building a detector. DetectionPipeline still checks the instances it is given.
    private static void RejectRedactOnNonRedactingDetectors(SentinelOptions opts, string paramName)
    {
        foreach (var (type, cfg) in opts.GetDetectorConfigurations())
        {
            if (cfg.Enabled != false && cfg.Action == SentinelAction.Redact && !typeof(IRedactingDetector).IsAssignableFrom(type))
            {
                throw new ArgumentException(
                    $"AI.Sentinel: detector {type.Name} is configured with Action = Redact but does not implement IRedactingDetector. " +
                    "Only detectors that can locate their match can redact.",
                    paramName);
            }
        }
    }

    // Thresholds are honoured only by semantic detectors; on any other detector they would silently do nothing.
    // A threshold left unset takes the detector's built-in value, which only the instance knows, so a pair
    // that mixes the two is checked again by DetectionPipeline when it is built.
    private static void RejectInvalidThresholds(SentinelOptions opts, string paramName)
    {
        foreach (var (type, cfg) in opts.GetDetectorConfigurations())
        {
            if (cfg.HighThreshold is null && cfg.MediumThreshold is null) continue;

            if (!typeof(SemanticDetectorBase).IsAssignableFrom(type))
            {
                throw new ArgumentException(
                    $"AI.Sentinel: detector {type.Name} is configured with a HighThreshold or MediumThreshold but is not a semantic detector. " +
                    "Only SemanticDetectorBase detectors use similarity thresholds.",
                    paramName);
            }

            foreach (var (name, value) in new[] { ("HighThreshold", cfg.HighThreshold), ("MediumThreshold", cfg.MediumThreshold) })
            {
                if (value is { } v && !(v > 0f && v <= 1f))
                {
                    throw new ArgumentException(
                        $"AI.Sentinel: detector {type.Name} has {name} {v}. A similarity threshold must be greater than 0 and at most 1.",
                        paramName);
                }
            }

            if (cfg.HighThreshold is { } high && cfg.MediumThreshold is { } medium && medium > high)
            {
                throw new ArgumentException(
                    $"AI.Sentinel: detector {type.Name} has MediumThreshold {medium} above HighThreshold {high}. Medium must not exceed High.",
                    paramName);
            }
        }
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

    private static IDetectionPipeline BuildDetectionPipeline(
        SentinelOptions opts, IServiceProvider sp, EmbeddingScope? embeddingScope)
        => new DetectionPipelineInstrumented(
            new DetectionPipeline(
                sp.GetServices<IDetector>(),
                opts.GetDetectorConfigurations(),
                opts.EscalationClient,
                sp.GetService<ILogger<DetectionPipeline>>(),
                opts.OnDetectorFailure,
                opts.RedactByDefault,
                embeddingScope: embeddingScope));

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

        var approvalStore = ApprovalStoreAuditing.Resolve(sp);
        RejectCallScopedGrantsOnRoleActivationStore(approvalStore, bindings);
        return new DefaultToolCallGuard(bindings, policyByName, opts.DefaultToolPolicy, approvalStore, logger);
    }

    private static void RejectCallScopedGrantsOnRoleActivationStore(IApprovalStore? approvalStore, IReadOnlyList<ToolCallPolicyBinding> bindings)
    {
        var active = approvalStore is AuditingApprovalStore auditing ? auditing.Inner : approvalStore;
        if (active is not IRoleActivationApprovalStore store)
        {
            return;
        }

        var callScoped = bindings.FirstOrDefault(b => b.ApprovalSpec?.GrantScope == ApprovalGrantScope.Call);
        if (callScoped is not null)
        {
            throw new InvalidOperationException(
                $"The approval rule for '{callScoped.Pattern}' uses GrantScope.Call, which the {store.BackendName} approval store " +
                "cannot honour: a role activation covers a time window and knows nothing of tool arguments. " +
                "Use GrantScope.Rule, or a store that grants per call.");
        }
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
            if (reg.DetectorType is { } detectorType)
            {
                // A type-based registration carries no per-instance state, and Configure<T> is keyed by
                // type, so a repeat of the same type is always redundant. This happens for real via the
                // shared base-config recipe in the README's "Named pipelines" section: one
                // Action<SentinelOptions> containing AddDetector<T>(), applied to the default pipeline
                // and to each named one. Factory registrations are left alone — two factories may
                // legitimately produce differently-constructed instances of the same type.
                services.TryAddEnumerable(ServiceDescriptor.Singleton(typeof(IDetector), detectorType));
            }
            else
            {
                // The DetectorRegistration constructor guarantees a factory when there is no type.
                var factory = reg.Factory!;
                services.AddSingleton<IDetector>(sp => factory(sp));
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
            // An approval binding names its approval rule, not a registered policy.
            if (binding.ApprovalSpec is null && !policiesByName.ContainsKey(binding.PolicyName))
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

            return BuildNamedChatClient(sp, name, inner);
        });

    private static SentinelChatClient BuildNamedChatClient(IServiceProvider sp, string name, IChatClient inner) =>
        new(BuildNamedSentinelPipeline(sp, name, inner));

    private static SentinelPipeline BuildNamedSentinelPipeline(IServiceProvider sp, string name, IChatClient inner)
    {
        // First: building the keyed detection pipeline or engine also needs the shared services.
        RequireSharedInfrastructure(sp, name);
        var opts = sp.GetRequiredKeyedService<SentinelOptions>(name);
        var pipeline = sp.GetRequiredKeyedService<IDetectionPipeline>(name);
        var engine = sp.GetRequiredKeyedService<InterventionEngine>(name);
        WarnIfSemanticDetectionInert(sp, opts, pipelineName: name);

        return new SentinelPipeline(
            inner,
            pipeline,
            sp.GetRequiredService<IAuditStore>(),     // shared
            engine,
            opts,
            sp.GetRequiredService<IAlertSink>(),      // shared
            sp.GetServices<IAuditForwarder>(),        // shared
            pipelineName: name);
    }

    // Shared infrastructure (audit store, alert sink, forwarders) is registered ONLY
    // by the default unnamed AddAISentinel(...) call. Surface a clearer error than
    // "No service for type 'IAuditStore' has been registered" if the user skipped it.
    // We probe IAuditStore as the canary — if it's missing, the alert sink and
    // forwarders are almost certainly missing too.
    private static void RequireSharedInfrastructure(IServiceProvider sp, string name)
    {
        if (sp.GetService<IAuditStore>() is null)
        {
            throw new InvalidOperationException(
                $"AI.Sentinel pipeline '{name}': shared infrastructure (IAuditStore, IAlertSink, IAuditForwarder) is missing. Call services.AddAISentinel(...) once before registering or resolving named pipelines — the default unnamed call wires the shared audit store, forwarders, and alert sink.");
        }
    }

    /// <summary>Builds the "semantic detection is inert" warning, or <see langword="null"/> when it is active.</summary>
    /// <remarks>A pipeline is judged on its effective generator: its own, or for a named pipeline without one the
    /// default pipeline's, set or taken from the container.</remarks>
    private static string? InertSemanticWarning(SentinelOptions? opts, IServiceProvider sp, string? pipelineName)
    {
        var generator = pipelineName is null
            ? opts?.EmbeddingGenerator
            : opts?.EmbeddingGenerator ?? sp.GetService<SentinelOptions>()?.EmbeddingGenerator;
        if (opts is null || generator is not null)
        {
            return null;
        }

        var count = CountInertSemantic(opts, sp.GetServices<IDetector>());
        if (count == 0)
        {
            return null;
        }

        return InertSemanticMessage(count, pipelineName);
    }

    /// <summary>Semantic detectors without a rule layer that this pipeline would run: an opt-in detector left
    /// off is not inert, it is simply not running.</summary>
    private static int CountInertSemantic(SentinelOptions opts, IEnumerable<IDetector> detectors)
    {
        var configurations = opts.GetDetectorConfigurations();
        return detectors.Count(d => d is SemanticDetectorBase { HasRuleFastPath: false }
            && DetectorConfiguration.IsEnabled(d, configurations.GetValueOrDefault(d.GetType())));
    }

    private static string InertSemanticMessage(int count, string? pipelineName)
    {
        var scope = pipelineName is null ? "AI.Sentinel" : $"AI.Sentinel pipeline '{pipelineName}'";
        // SEC-01 and SEC-05 are deliberately excluded from the count: their rule layer fires without
        // a generator, so naming them here would contradict the Critical block the very next line of
        // output may carry.
        var hint = pipelineName is null
            ? "Set SENTINEL_EMBEDDING_ENDPOINT and SENTINEL_EMBEDDING_MODEL, set SentinelOptions.EmbeddingGenerator, or register an IEmbeddingGenerator<string, Embedding<float>> in the container with UseEmbeddingGeneratorFromServices left on to enable the rest."
            : "Set EmbeddingGenerator on this pipeline's options or on the default AddAISentinel call, or register an IEmbeddingGenerator<string, Embedding<float>> in the container with UseEmbeddingGeneratorFromServices left on for the default pipeline.";
        return $"{scope}: EmbeddingGenerator is not configured — {count} semantic detectors return Clean on every scan. SEC-01 PromptInjection and SEC-05 Jailbreak still catch the unambiguous phrasings through their rule layer, but paraphrases go undetected. {hint}";
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

        var count = CountInertSemantic(options, detectors);
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
