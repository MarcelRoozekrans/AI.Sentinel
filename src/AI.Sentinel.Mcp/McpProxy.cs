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
/// <c>prompts/list</c>, <c>prompts/get</c>, <c>resources/list</c>, and
/// <c>resources/read</c> request is forwarded to the upstream client verbatim.
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
        CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(hostTransport);
        ArgumentNullException.ThrowIfNull(targetTransport);
        ArgumentNullException.ThrowIfNull(config);

        var targetClient = await McpClient.CreateAsync(
            clientTransport: targetTransport,
            clientOptions: null,
            loggerFactory: NullLoggerFactory.Instance,
            cancellationToken: ct).ConfigureAwait(false);
        await using var _targetDispose = targetClient.ConfigureAwait(false);

        // Pipeline is constructed now so Tasks 7/8 can drop filters on top
        // without rewiring the handler closure. Unused in forward-only mode.
        _ = McpPipelineFactory.Create(config, preset);
        _ = maxScanBytes;

        var serverOptions = BuildServerOptions(targetClient);

        var server = McpServer.Create(
            hostTransport,
            serverOptions,
            loggerFactory: NullLoggerFactory.Instance,
            serviceProvider: null);
        await using var _serverDispose = server.ConfigureAwait(false);

        await server.RunAsync(ct).ConfigureAwait(false);
    }

    private static McpServerOptions BuildServerOptions(McpClient targetClient) => new()
    {
        ServerInfo = new Implementation { Name = "sentinel-mcp", Version = "0.1.0" },
        Capabilities = new ServerCapabilities
        {
            Tools     = new ToolsCapability(),
            Prompts   = new PromptsCapability(),
            Resources = new ResourcesCapability(),
        },
        Handlers = BuildForwardingHandlers(targetClient),
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

        ListResourcesHandler = async (req, c) =>
        {
            var resources = await targetClient.ListResourcesAsync(cancellationToken: c).ConfigureAwait(false);
            return new ListResourcesResult { Resources = resources.Select(r => r.ProtocolResource).ToList() };
        },

        ReadResourceHandler = async (req, c) =>
            await targetClient.ReadResourceAsync(
                uri: req.Params!.Uri,
                cancellationToken: c).ConfigureAwait(false),
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
