using System.Globalization;
using System.Text.Json;
using Microsoft.Extensions.AI;
using AI.Sentinel.Approvals;
using AI.Sentinel.Audit;
using AI.Sentinel.Authorization;
using AI.Sentinel.ClaudeCode;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using AI.Sentinel.Mcp.Logging;
using AI.Sentinel.Redaction;
using Microsoft.Extensions.Logging.Abstractions;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using ZeroAlloc.Authorization;

using AI.Sentinel.Embeddings;
using AI.Sentinel.Review;

namespace AI.Sentinel.Mcp;

/// <summary>
/// Runs the Sentinel MCP proxy — host ⇆ server side ⇆ (filters in later tasks)
/// ⇆ client side ⇆ target.
/// </summary>
/// <remarks>
/// Capabilities are mirrored from the upstream target: <c>tools/*</c>,
/// <c>prompts/*</c>, and <c>resources/*</c> are advertised to the host
/// only when the target also advertises them. <c>tools/call</c>,
/// <c>prompts/get</c>, and <c>resources/read</c> are pre/post-scanned by
/// <see cref="ToolCallInterceptor"/>, <see cref="PromptGetInterceptor"/>,
/// and <see cref="ResourceReadInterceptor"/> respectively; list/template
/// metadata calls forward verbatim. When <see cref="RunAsync"/> is given an
/// <see cref="IToolCallGuard"/>, an authorization gate runs before the detection
/// pipeline on every <c>tools/call</c>.
/// Internal: the <c>sentinel-mcp</c> CLI is the supported entry point.
/// </remarks>
internal static class McpProxy
{
    /// <summary>Runs the proxy until <paramref name="ct"/> is cancelled or the host transport closes.</summary>
    /// <param name="hostTransport">Transport facing the MCP host (typically stdio).</param>
    /// <param name="targetTransport">Transport facing the upstream MCP target server.</param>
    /// <param name="config">Severity-to-action mapping for detector findings.</param>
    /// <param name="preset">Detector bundle to load.</param>
    /// <param name="maxScanBytes">Per-request scan budget passed to the message builder.</param>
    /// <param name="stderr">Writer used for structured proxy log lines.</param>
    /// <param name="ct">Cancellation token observed by the running server.</param>
    /// <param name="embeddingGenerator">Optional embedding generator for embedding-aware detectors.</param>
    /// <param name="guard">Optional authorization guard. When supplied, runs before detection on <c>tools/call</c>.</param>
    /// <param name="callerResolver">Optional resolver mapping the inbound request to an <see cref="ISecurityContext"/>. Defaults to <see cref="EnvironmentSecurityContext.FromEnvironment"/>.</param>
    /// <param name="auditStore">Optional store for audit entries; defaults to an in-memory ring buffer. The caller owns and disposes it.</param>
    /// <param name="forwarders">Optional forwarders that mirror every audit entry. The caller owns them.</param>
    /// <param name="placeholderIdleExpiry">How long a placeholder the proxy minted stays known when unused; defaults to
    /// <see cref="PlaceholderStore.DefaultIdleExpiry"/>. Used only when <see cref="HookConfig.RedactToolResults"/> is set.</param>
    internal static Task RunAsync(
        ITransport hostTransport,
        IClientTransport targetTransport,
        HookConfig config,
        DetectorPreset preset,
        int maxScanBytes,
        TextWriter stderr,
        CancellationToken ct,
        IEmbeddingGenerator<string, Embedding<float>>? embeddingGenerator = null,
        IToolCallGuard? guard = null,
        Func<CallToolRequestParams, ISecurityContext>? callerResolver = null,
        IApprovalStore? approvalStore = null,
        TimeSpan? approvalWait = null,
        IAuditStore? auditStore = null,
        IReadOnlyList<IAuditForwarder>? forwarders = null,
        TimeSpan? placeholderIdleExpiry = null,
        IDetectionReviewer? reviewer = null)
        => RunWithSessionAsync(
            hostTransport: hostTransport,
            targetTransport: targetTransport,
            config: config,
            preset: preset,
            maxScanBytes: maxScanBytes,
            stderr: stderr,
            ct: ct,
            embeddingGenerator: embeddingGenerator,
            guard: guard,
            callerResolver: callerResolver,
            approvalStore: approvalStore,
            approvalWait: approvalWait,
            auditStore: auditStore,
            forwarders: forwarders,
            sessionId: null,
            placeholderIdleExpiry: placeholderIdleExpiry,
            reviewer: reviewer);

    /// <summary>Same as <see cref="RunAsync"/> but lets tests fix the per-run session id.</summary>
    internal static async Task RunWithSessionAsync(
        ITransport hostTransport,
        IClientTransport targetTransport,
        HookConfig config,
        DetectorPreset preset,
        int maxScanBytes,
        TextWriter stderr,
        CancellationToken ct,
        IEmbeddingGenerator<string, Embedding<float>>? embeddingGenerator = null,
        IToolCallGuard? guard = null,
        Func<CallToolRequestParams, ISecurityContext>? callerResolver = null,
        IApprovalStore? approvalStore = null,
        TimeSpan? approvalWait = null,
        IAuditStore? auditStore = null,
        IReadOnlyList<IAuditForwarder>? forwarders = null,
        SessionId? sessionId = null,
        TimeSpan? placeholderIdleExpiry = null,
        IDetectionReviewer? reviewer = null)
    {
        ArgumentNullException.ThrowIfNull(hostTransport);
        ArgumentNullException.ThrowIfNull(targetTransport);
        ArgumentNullException.ThrowIfNull(config);
        ArgumentNullException.ThrowIfNull(stderr);

        var targetClient = await McpClient.CreateAsync(
            clientTransport: targetTransport,
            clientOptions: null,
            loggerFactory: NullLoggerFactory.Instance,
            cancellationToken: ct).ConfigureAwait(false);
        try
        {
            // The proxy is long-lived, so it pays the embedding cost once — but it still shares the
            // example cache so a restart is cheap.
            var environment = ReadEnvironment();
            string? embeddingError = null;
            using var embeddings = embeddingGenerator is null
                ? SentinelEmbeddingSetup.TryCreateFromEnvironment(environment, out embeddingError)
                : null;
            if (embeddingError is not null)
            {
                await stderr.WriteLineAsync(embeddingError).ConfigureAwait(false);
            }

            using var review = await ResolveReviewAsync(reviewer, environment, stderr).ConfigureAwait(false);
            var reviewLimits = ReviewLimitsFor(review);
            var pipeline = McpPipelineFactory.Create(
                config, preset, embeddingGenerator ?? embeddings?.Generator,
                out var pipelineStore, out var inertSemanticWarning, out var unreviewedSemanticWarning, embeddings?.ExampleCache,
                ReportDetectorFailure, auditStore, forwarders, reviewer ?? review?.Reviewer, reviewLimits);

            await WriteSemanticWarningAsync(config, "semantic_detection_inert", inertSemanticWarning, stderr).ConfigureAwait(false);
            await WriteSemanticWarningAsync(config, "semantic_detection_unreviewed", unreviewedSemanticWarning, stderr).ConfigureAwait(false);
            var placeholders = CreatePlaceholderStore(config, placeholderIdleExpiry);

            // One session per proxy process: every scan and authorization entry of this run shares it.
            var serverOptions = BuildServerOptions(targetClient, pipeline, maxScanBytes, stderr, guard, pipelineStore, forwarders, callerResolver, approvalStore, approvalWait, sessionId ?? SessionId.New(), placeholders);

            var server = McpServer.Create(
                hostTransport,
                serverOptions,
                loggerFactory: NullLoggerFactory.Instance,
                serviceProvider: null);
            await using var _serverDispose = server.ConfigureAwait(false);

            await server.RunAsync(ct).ConfigureAwait(false);
        }
        finally
        {
            // Wrap target client disposal (which owns the upstream transport / child process)
            // with a grace period so a hung target can't deadlock proxy shutdown.
            await DisposeWithGraceAsync(targetClient, GetShutdownGrace()).ConfigureAwait(false);
        }
    }

    /// <summary>A caller-supplied reviewer wins; otherwise read SENTINEL_REVIEW_*. Without a reviewer a semantic hit is
    /// capped at Medium, so the proxy can only forward it with a warning. A bad setting is reported by name.</summary>
    private static async Task<SentinelReviewSetup?> ResolveReviewAsync(
        IDetectionReviewer? supplied, IReadOnlyDictionary<string, string?> environment, TextWriter stderr)
    {
        if (supplied is not null) return null;

        var setup = SentinelReviewSetup.TryCreateFromEnvironment(environment, out var error);
        if (error is not null)
        {
            await stderr.WriteLineAsync(error).ConfigureAwait(false);
        }

        return setup;
    }

    /// <summary>The proxy keeps the library defaults, 5 s and 4 reviews, for what the setting leaves unset.</summary>
    internal static ReviewLimits? ReviewLimitsFor(SentinelReviewSetup? review)
    {
        if (review is null) return null;
        var defaults = new SentinelOptions();
        return new ReviewLimits(review.MaxReviewsPerScan ?? defaults.MaxReviewsPerScan, review.ReviewTimeout ?? defaults.ReviewTimeout);
    }

    /// <summary>
    /// No logging provider here either — surface it on stderr so an inert SEC-01 isn't mistaken
    /// for a clean scan. Routed through StderrLogger because this stream is structured
    /// (key=value, or NDJSON under SENTINEL_MCP_LOG_JSON=1); raw prose would break consumers.
    /// Emitted once per proxy process. Suppressible via SENTINEL_HOOK_SUPPRESS_SEMANTIC_WARNING.
    /// </summary>
    private static async Task WriteSemanticWarningAsync(HookConfig config, string eventName, string? warning, TextWriter stderr)
    {
        if (config.SuppressSemanticWarning || warning is null)
        {
            return;
        }

        await stderr.WriteLineAsync(StderrLogger.Format(new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["event"] = eventName,
            ["detail"] = warning,
        })).ConfigureAwait(false);
    }

    /// <summary>
    /// One placeholder store per run, shared by the three interceptors, so a placeholder minted in one response is
    /// known to every later one. Null when <see cref="HookConfig.RedactToolResults"/> is off, which keeps the 3.0
    /// scan and fallback.
    /// </summary>
    internal static PlaceholderStore? CreatePlaceholderStore(HookConfig config, TimeSpan? placeholderIdleExpiry)
        => config.RedactToolResults
            ? new PlaceholderStore(placeholderIdleExpiry ?? PlaceholderStore.DefaultIdleExpiry)
            : null;

    /// <summary>
    /// Subprocess shutdown grace from <c>SENTINEL_MCP_TIMEOUT_SEC</c>; defaults to 5 seconds.
    /// Falls back to default on garbage / non-positive values.
    /// </summary>
    internal static TimeSpan GetShutdownGrace()
    {
        var raw = Environment.GetEnvironmentVariable("SENTINEL_MCP_TIMEOUT_SEC");
        if (int.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var v) && v > 0)
        {
            return TimeSpan.FromSeconds(v);
        }
        return TimeSpan.FromSeconds(5);
    }

    /// <summary>
    /// Disposes <paramref name="transport"/> with a grace period. If disposal doesn't complete
    /// within <paramref name="grace"/>, logs and returns. Does NOT kill the child process —
    /// that requires SDK transport wrapping (deferred to backlog).
    /// </summary>
    internal static async Task DisposeWithGraceAsync(IAsyncDisposable transport, TimeSpan grace)
    {
        ArgumentNullException.ThrowIfNull(transport);

        var disposeTask = transport.DisposeAsync().AsTask();
        var graceTask = Task.Delay(grace);
        var winner = await Task.WhenAny(disposeTask, graceTask).ConfigureAwait(false);
        if (winner != disposeTask)
        {
            StderrLogger.Log(new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["event"] = "transport_dispose",
                ["action"] = "grace_expired",
                ["grace_s"] = grace.TotalSeconds.ToString("0", CultureInfo.InvariantCulture),
            });
        }
    }

    /// <summary>A detector that fails is skipped for that scan rather than aborting it, but the
    /// operator has to learn a control was unavailable. Routed through StderrLogger so it joins the
    /// proxy's structured stream instead of breaking NDJSON consumers.</summary>
    private static void ReportDetectorFailure(string message) =>
        StderrLogger.Log(new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["event"] = "detector_failed",
            ["detail"] = message,
        });

    /// <summary>Embedding and review settings, read directly because they carry no host-specific prefix.</summary>
    private static Dictionary<string, string?> ReadEnvironment()
    {
        var env = new Dictionary<string, string?>(StringComparer.Ordinal);
        foreach (System.Collections.DictionaryEntry entry in Environment.GetEnvironmentVariables())
        {
            if (entry.Key is string key && (key.StartsWith("SENTINEL_EMBEDDING_", StringComparison.Ordinal)
                || key.StartsWith("SENTINEL_REVIEW_", StringComparison.Ordinal)))
            {
                env[key] = entry.Value as string;
            }
        }

        return env;
    }

    private static McpServerOptions BuildServerOptions(
        McpClient targetClient,
        SentinelPipeline pipeline,
        int maxScanBytes,
        TextWriter stderr,
        IToolCallGuard? guard,
        IAuditStore? auditStore,
        IReadOnlyList<IAuditForwarder>? forwarders,
        Func<CallToolRequestParams, ISecurityContext>? callerResolver,
        IApprovalStore? approvalStore,
        TimeSpan? approvalWait,
        SessionId sessionId,
        PlaceholderStore? placeholders)
    {
        var targetCaps = targetClient.ServerCapabilities;
        var capabilities = new ServerCapabilities();
        var handlers = new McpServerHandlers();
        var requestFilters = new McpRequestFilters();

        if (targetCaps.Tools is not null)
        {
            WireTools(targetClient, pipeline, maxScanBytes, stderr, guard, auditStore, forwarders, callerResolver,
                approvalStore, approvalWait, sessionId, placeholders, capabilities, handlers, requestFilters);
        }

        if (targetCaps.Prompts is not null)
        {
            WirePrompts(targetClient, pipeline, maxScanBytes, stderr, sessionId, placeholders,
                capabilities, handlers, requestFilters);
        }

        if (targetCaps.Resources is not null)
        {
            WireResources(targetClient, pipeline, targetCaps.Resources, maxScanBytes, sessionId, placeholders,
                capabilities, handlers, requestFilters);
        }

        return new McpServerOptions
        {
            ServerInfo = new Implementation { Name = "sentinel-mcp", Version = "0.1.0" },
            Capabilities = capabilities,
            Handlers = handlers,
            Filters = new McpServerFilters { Request = requestFilters },
        };
    }

    private static void WireTools(
        McpClient targetClient,
        SentinelPipeline pipeline,
        int maxScanBytes,
        TextWriter stderr,
        IToolCallGuard? guard,
        IAuditStore? auditStore,
        IReadOnlyList<IAuditForwarder>? forwarders,
        Func<CallToolRequestParams, ISecurityContext>? callerResolver,
        IApprovalStore? approvalStore,
        TimeSpan? approvalWait,
        SessionId sessionId,
        PlaceholderStore? placeholders,
        ServerCapabilities capabilities,
        McpServerHandlers handlers,
        McpRequestFilters requestFilters)
    {
        capabilities.Tools = new ToolsCapability();
        handlers.CallToolHandler = (req, c) =>
            targetClient.CallToolAsync(
                toolName: req.Params!.Name,
                arguments: ToObjectDictionary(req.Params.Arguments),
                cancellationToken: c);
        handlers.ListToolsHandler = async (req, c) =>
        {
            var tools = await targetClient.ListToolsAsync(cancellationToken: c).ConfigureAwait(false);
            return new ListToolsResult { Tools = tools.Select(t => t.ProtocolTool).ToList() };
        };
        requestFilters.CallToolFilters.Add(
            ToolCallInterceptor.Create(pipeline, maxScanBytes, stderr, guard, auditStore, callerResolver,
                approvalStore, approvalWait, forwarders, sessionId, placeholders));
    }

    private static void WirePrompts(
        McpClient targetClient,
        SentinelPipeline pipeline,
        int maxScanBytes,
        TextWriter stderr,
        SessionId sessionId,
        PlaceholderStore? placeholders,
        ServerCapabilities capabilities,
        McpServerHandlers handlers,
        McpRequestFilters requestFilters)
    {
        capabilities.Prompts = new PromptsCapability();
        handlers.GetPromptHandler = (req, c) =>
            targetClient.GetPromptAsync(
                name: req.Params!.Name,
                arguments: ToObjectDictionary(req.Params.Arguments),
                cancellationToken: c);
        handlers.ListPromptsHandler = async (req, c) =>
        {
            var prompts = await targetClient.ListPromptsAsync(cancellationToken: c).ConfigureAwait(false);
            return new ListPromptsResult { Prompts = prompts.Select(p => p.ProtocolPrompt).ToList() };
        };
        requestFilters.GetPromptFilters.Add(
            PromptGetInterceptor.Create(pipeline, maxScanBytes, stderr, sessionId, placeholders));
    }

    private static void WireResources(
        McpClient targetClient,
        SentinelPipeline pipeline,
        ResourcesCapability targetResources,
        int maxScanBytes,
        SessionId sessionId,
        PlaceholderStore? placeholders,
        ServerCapabilities capabilities,
        McpServerHandlers handlers,
        McpRequestFilters requestFilters)
    {
        capabilities.Resources = new ResourcesCapability
        {
            ListChanged = targetResources.ListChanged,
            Subscribe = targetResources.Subscribe,
        };
        handlers.ListResourcesHandler = (req, c) =>
            targetClient.ListResourcesAsync(req.Params, c);
        handlers.ListResourceTemplatesHandler = (req, c) =>
            targetClient.ListResourceTemplatesAsync(req.Params, c);
        handlers.ReadResourceHandler = (req, c) =>
            targetClient.ReadResourceAsync(req.Params!, c);
        requestFilters.ReadResourceFilters.Add(
            ResourceReadInterceptor.Create(pipeline, maxScanBytes, sessionId, placeholders));
    }

    private static Dictionary<string, object?> ToObjectDictionary(
        IDictionary<string, JsonElement>? args)
    {
        if (args is null || args.Count == 0)
        {
            return EmptyArgs;
        }

        var dict = new Dictionary<string, object?>(args.Count, StringComparer.Ordinal);
        foreach (var (k, v) in args)
        {
            dict[k] = v;
        }

        return dict;
    }

    private static readonly Dictionary<string, object?> EmptyArgs =
        new(StringComparer.Ordinal);

    /// <summary>
    /// Constructs the appropriate <see cref="IClientTransport"/> for <paramref name="target"/>.
    /// HTTP/HTTPS URLs return an <see cref="HttpClientTransport"/> (Streamable HTTP / SSE auto-detect)
    /// with optional headers from <c>SENTINEL_MCP_HTTP_HEADERS</c>; anything else returns a
    /// <see cref="StdioClientTransport"/> launching <paramref name="target"/> with <paramref name="arguments"/>.
    /// Emits a <c>transport_init</c> log line on stderr.
    /// </summary>
    internal static IClientTransport CreateClientTransport(string target, IList<string>? arguments = null)
    {
        ArgumentNullException.ThrowIfNull(target);

        if (IsHttpUrl(target))
        {
            var headers = ParseHttpHeaders(Environment.GetEnvironmentVariable("SENTINEL_MCP_HTTP_HEADERS"), out var skipped);
            var initLog = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["event"] = "transport_init",
                ["transport"] = "http",
                ["endpoint"] = target,
                ["headers"] = headers.Count.ToString(System.Globalization.CultureInfo.InvariantCulture),
            };
            if (skipped > 0)
                initLog["headers_skipped"] = skipped.ToString(System.Globalization.CultureInfo.InvariantCulture);
            StderrLogger.Log(initLog);
            return new HttpClientTransport(new HttpClientTransportOptions
            {
                Endpoint = new Uri(target),
                AdditionalHeaders = headers,
                Name = target,
            });
        }

        StderrLogger.Log(new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["event"] = "transport_init",
            ["transport"] = "stdio",
            ["command"] = target,
        });
        return new StdioClientTransport(
            new StdioClientTransportOptions
            {
                Command = target,
                Arguments = arguments ?? Array.Empty<string>(),
                Name = target,
            },
            loggerFactory: null);
    }

    /// <summary>True when the target string is an HTTP/HTTPS URL. Scheme match is case-insensitive per RFC 3986.</summary>
    internal static bool IsHttpUrl(string target)
    {
        if (string.IsNullOrWhiteSpace(target)) return false;
        return target.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
            || target.StartsWith("https://", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Parses a <c>SENTINEL_MCP_HTTP_HEADERS</c> string of the form <c>key=value;key=value</c>
    /// into a header dictionary. Malformed pairs (no <c>=</c>) are dropped and counted in
    /// the returned <paramref name="skipped"/>; callers may surface that count via stderr.
    /// </summary>
    internal static IDictionary<string, string> ParseHttpHeaders(string? raw, out int skipped)
    {
        skipped = 0;
        var d = new Dictionary<string, string>(StringComparer.Ordinal);
        if (string.IsNullOrWhiteSpace(raw)) return d;
        foreach (var pair in raw.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var idx = pair.IndexOf('=', StringComparison.Ordinal);
            if (idx <= 0)
            {
                skipped++;
                continue;
            }
            var key = pair[..idx].Trim();
            var value = pair[(idx + 1)..].Trim();
            if (key.Length == 0)
            {
                skipped++;
                continue;
            }
            d[key] = value;
        }
        return d;
    }

    /// <summary>Convenience overload that discards the <c>skipped</c> count. Used by tests that don't care.</summary>
    internal static IDictionary<string, string> ParseHttpHeaders(string? raw)
        => ParseHttpHeaders(raw, out _);
}
