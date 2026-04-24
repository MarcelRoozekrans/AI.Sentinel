using System.Text.Json;
using AI.Sentinel.ClaudeCode;
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
/// Forward-only in v1 Task 6: every <c>tools/list</c>, <c>tools/call</c>,
/// <c>prompts/list</c>, and <c>prompts/get</c> request is forwarded to the
/// upstream client verbatim. Resources (<c>resources/list</c>,
/// <c>resources/read</c>) are deferred to v2 — the proxy does not advertise
/// the capability, so the SDK replies with <c>MethodNotFound</c> (-32601).
/// Sentinel filters land in Tasks 7 and 8.
/// </remarks>
public static class McpProxy
{
    /// <summary>Runs the proxy until <paramref name="ct"/> is cancelled or the host transport closes.</summary>
    public static async Task RunAsync(
        ITransport hostTransport,
        IClientTransport targetTransport,
        HookConfig config,
        McpDetectorPreset preset,
        int maxScanBytes,
        TextWriter stderr,
        CancellationToken ct)
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
        await using var _targetDispose = targetClient.ConfigureAwait(false);

        var pipeline = McpPipelineFactory.Create(config, preset);

        var serverOptions = BuildServerOptions(targetClient, pipeline, maxScanBytes, stderr);

        var server = McpServer.Create(
            hostTransport,
            serverOptions,
            loggerFactory: NullLoggerFactory.Instance,
            serviceProvider: null);
        await using var _serverDispose = server.ConfigureAwait(false);

        await server.RunAsync(ct).ConfigureAwait(false);
    }

    private static McpServerOptions BuildServerOptions(
        McpClient targetClient,
        SentinelPipeline pipeline,
        int maxScanBytes,
        TextWriter stderr) => new()
    {
        ServerInfo = new Implementation { Name = "sentinel-mcp", Version = "0.1.0" },
        Capabilities = new ServerCapabilities
        {
            Tools   = new ToolsCapability(),
            Prompts = new PromptsCapability(),
        },
        Handlers = BuildForwardingHandlers(targetClient),
        Filters  = new McpServerFilters
        {
            Request = new McpRequestFilters
            {
                CallToolFilters =
                {
                    ToolCallInterceptor.Create(pipeline, maxScanBytes, stderr),
                },
            },
        },
    };

    private static McpServerHandlers BuildForwardingHandlers(McpClient targetClient) => new()
    {
        CallToolHandler = async (req, c) =>
            await targetClient.CallToolAsync(
                toolName: req.Params!.Name,
                arguments: ToObjectDictionary(req.Params.Arguments),
                cancellationToken: c).ConfigureAwait(false),

        GetPromptHandler = async (req, c) =>
            await targetClient.GetPromptAsync(
                name: req.Params!.Name,
                arguments: ToObjectDictionary(req.Params.Arguments),
                cancellationToken: c).ConfigureAwait(false),

        ListToolsHandler = async (req, c) =>
        {
            var tools = await targetClient.ListToolsAsync(cancellationToken: c).ConfigureAwait(false);
            return new ListToolsResult { Tools = tools.Select(t => t.ProtocolTool).ToList() };
        },

        ListPromptsHandler = async (req, c) =>
        {
            var prompts = await targetClient.ListPromptsAsync(cancellationToken: c).ConfigureAwait(false);
            return new ListPromptsResult { Prompts = prompts.Select(p => p.ProtocolPrompt).ToList() };
        },
    };

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
}
