using System.Globalization;
using System.Text.Json;
using Microsoft.Extensions.AI;
using AI.Sentinel.Approvals;
using AI.Sentinel.Audit;
using AI.Sentinel.Authorization;
using AI.Sentinel.ClaudeCode;
using AI.Sentinel.Mcp.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

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
/// metadata calls forward verbatim. When an <see cref="IToolCallGuard"/>
/// is supplied via the <paramref name="guard"/> parameter on <see cref="RunAsync"/>,
/// an authorization gate runs before the detection pipeline on every
/// <c>tools/call</c>.
/// </remarks>
public static class McpProxy
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
    public static async Task RunAsync(
        ITransport hostTransport,
        IClientTransport targetTransport,
        HookConfig config,
        McpDetectorPreset preset,
        int maxScanBytes,
        TextWriter stderr,
        CancellationToken ct,
        IEmbeddingGenerator<string, Embedding<float>>? embeddingGenerator = null,
        IToolCallGuard? guard = null,
        Func<CallToolRequestParams, ISecurityContext>? callerResolver = null,
        IApprovalStore? approvalStore = null,
        TimeSpan? approvalWait = null)
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
            var pipeline = McpPipelineFactory.Create(config, preset, embeddingGenerator, out var auditStore);

            var serverOptions = BuildServerOptions(targetClient, pipeline, maxScanBytes, stderr, guard, auditStore, callerResolver, approvalStore, approvalWait);

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
        var graceTask   = Task.Delay(grace);
        var winner      = await Task.WhenAny(disposeTask, graceTask).ConfigureAwait(false);
        if (winner != disposeTask)
        {
            StderrLogger.Log(new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["event"]   = "transport_dispose",
                ["action"]  = "grace_expired",
                ["grace_s"] = grace.TotalSeconds.ToString("0", CultureInfo.InvariantCulture),
            });
        }
    }

    private static McpServerOptions BuildServerOptions(
        McpClient targetClient,
        SentinelPipeline pipeline,
        int maxScanBytes,
        TextWriter stderr,
        IToolCallGuard? guard,
        IAuditStore? auditStore,
        Func<CallToolRequestParams, ISecurityContext>? callerResolver,
        IApprovalStore? approvalStore,
        TimeSpan? approvalWait)
    {
        var targetCaps = targetClient.ServerCapabilities;
        var capabilities = new ServerCapabilities();
        var handlers = new McpServerHandlers();
        var requestFilters = new McpRequestFilters();

        if (targetCaps.Tools is not null)
        {
            WireTools(targetClient, pipeline, maxScanBytes, stderr, guard, auditStore, callerResolver,
                approvalStore, approvalWait, capabilities, handlers, requestFilters);
        }

        if (targetCaps.Prompts is not null)
        {
            WirePrompts(targetClient, pipeline, maxScanBytes, stderr,
                capabilities, handlers, requestFilters);
        }

        if (targetCaps.Resources is not null)
        {
            WireResources(targetClient, pipeline, targetCaps.Resources,
                capabilities, handlers, requestFilters);
        }

        return new McpServerOptions
        {
            ServerInfo   = new Implementation { Name = "sentinel-mcp", Version = "0.1.0" },
            Capabilities = capabilities,
            Handlers     = handlers,
            Filters      = new McpServerFilters { Request = requestFilters },
        };
    }

    private static void WireTools(
        McpClient targetClient,
        SentinelPipeline pipeline,
        int maxScanBytes,
        TextWriter stderr,
        IToolCallGuard? guard,
        IAuditStore? auditStore,
        Func<CallToolRequestParams, ISecurityContext>? callerResolver,
        IApprovalStore? approvalStore,
        TimeSpan? approvalWait,
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
                approvalStore, approvalWait));
    }

    private static void WirePrompts(
        McpClient targetClient,
        SentinelPipeline pipeline,
        int maxScanBytes,
        TextWriter stderr,
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
            PromptGetInterceptor.Create(pipeline, maxScanBytes, stderr));
    }

    private static void WireResources(
        McpClient targetClient,
        SentinelPipeline pipeline,
        ResourcesCapability targetResources,
        ServerCapabilities capabilities,
        McpServerHandlers handlers,
        McpRequestFilters requestFilters)
    {
        capabilities.Resources = new ResourcesCapability
        {
            ListChanged = targetResources.ListChanged,
            Subscribe   = targetResources.Subscribe,
        };
        handlers.ListResourcesHandler = (req, c) =>
            targetClient.ListResourcesAsync(req.Params, c);
        handlers.ListResourceTemplatesHandler = (req, c) =>
            targetClient.ListResourceTemplatesAsync(req.Params, c);
        handlers.ReadResourceHandler = (req, c) =>
            targetClient.ReadResourceAsync(req.Params!, c);
        requestFilters.ReadResourceFilters.Add(
            ResourceReadInterceptor.Create(pipeline));
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
    public static IClientTransport CreateClientTransport(string target, IList<string>? arguments = null)
    {
        ArgumentNullException.ThrowIfNull(target);

        if (IsHttpUrl(target))
        {
            var headers = ParseHttpHeaders(Environment.GetEnvironmentVariable("SENTINEL_MCP_HTTP_HEADERS"), out var skipped);
            var initLog = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["event"]     = "transport_init",
                ["transport"] = "http",
                ["endpoint"]  = target,
                ["headers"]   = headers.Count.ToString(System.Globalization.CultureInfo.InvariantCulture),
            };
            if (skipped > 0)
                initLog["headers_skipped"] = skipped.ToString(System.Globalization.CultureInfo.InvariantCulture);
            StderrLogger.Log(initLog);
            return new HttpClientTransport(new HttpClientTransportOptions
            {
                Endpoint          = new Uri(target),
                AdditionalHeaders = headers,
                Name              = target,
            });
        }

        StderrLogger.Log(new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["event"]     = "transport_init",
            ["transport"] = "stdio",
            ["command"]   = target,
        });
        return new StdioClientTransport(
            new StdioClientTransportOptions
            {
                Command   = target,
                Arguments = arguments ?? Array.Empty<string>(),
                Name      = target,
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
            var key   = pair[..idx].Trim();
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
