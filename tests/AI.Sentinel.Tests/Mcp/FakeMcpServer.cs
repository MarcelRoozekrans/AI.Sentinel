using System.IO.Pipelines;
using System.Threading.Channels;
using Microsoft.Extensions.Logging.Abstractions;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

namespace AI.Sentinel.Tests.Mcp;

/// <summary>
/// In-memory MCP server + paired client transport for proxy tests.
/// Call <see cref="Start"/> to boot; it returns an <see cref="IClientTransport"/>
/// that the proxy under test connects to. Canned responses are queued via
/// <see cref="EnqueueToolResult"/> / <see cref="EnqueuePromptResult"/>; when the
/// queue is empty, defaults apply.
/// </summary>
/// <remarks>
/// <para>
/// This harness avoids spawning subprocesses — both ends run in-process over a
/// pair of <see cref="Pipe"/>s. The SDK ships a stream-based
/// <see cref="StreamClientTransport"/> in <c>ModelContextProtocol.Protocol</c>,
/// so no custom <see cref="IClientTransport"/> adapter is required.
/// </para>
/// <para>
/// Consumed by <c>McpProxy</c> tests; has no tests of its own. Kept public so
/// callers in the same test assembly can instantiate it without friction.
/// </para>
/// </remarks>
public sealed class FakeMcpServer : IAsyncDisposable
{
    private readonly Channel<CallToolResult> _toolResults = Channel.CreateUnbounded<CallToolResult>();
    private readonly Channel<GetPromptResult> _promptResults = Channel.CreateUnbounded<GetPromptResult>();

    private McpServer? _server;
    private Task? _runTask;
    private CancellationTokenSource? _cts;
    private Pipe? _fromProxy;
    private Pipe? _toProxy;

    private readonly List<CallToolRequestParams> _receivedToolCalls = [];
    private readonly List<GetPromptRequestParams> _receivedPromptGets = [];

    /// <summary>Tool calls the fake server has received, in order.</summary>
    public IReadOnlyList<CallToolRequestParams> ReceivedToolCalls => _receivedToolCalls;

    /// <summary>Prompt gets the fake server has received, in order.</summary>
    public IReadOnlyList<GetPromptRequestParams> ReceivedPromptGets => _receivedPromptGets;

    /// <summary>Queues a <see cref="CallToolResult"/> to be returned by the next <c>tools/call</c>.</summary>
    public void EnqueueToolResult(CallToolResult result) => _toolResults.Writer.TryWrite(result);

    /// <summary>Queues a <see cref="GetPromptResult"/> to be returned by the next <c>prompts/get</c>.</summary>
    public void EnqueuePromptResult(GetPromptResult result) => _promptResults.Writer.TryWrite(result);

    /// <summary>Starts the fake server and returns a client transport the proxy can connect to.</summary>
    public IClientTransport Start()
    {
        _fromProxy = new Pipe();
        _toProxy = new Pipe();

        var serverTransport = new StreamServerTransport(
            inputStream: _fromProxy.Reader.AsStream(),
            outputStream: _toProxy.Writer.AsStream(),
            serverName: "fake-mcp-server",
            loggerFactory: null);

        _server = McpServer.Create(
            serverTransport,
            BuildOptions(),
            loggerFactory: NullLoggerFactory.Instance,
            serviceProvider: null);

        _cts = new CancellationTokenSource();
        _runTask = _server.RunAsync(_cts.Token);

        // Pair: proxy reads from _toProxy (fake's output), writes to _fromProxy (fake's input).
        return new StreamClientTransport(
            serverInput: _fromProxy.Writer.AsStream(),
            serverOutput: _toProxy.Reader.AsStream(),
            loggerFactory: NullLoggerFactory.Instance);
    }

    private McpServerOptions BuildOptions() => new()
    {
        ServerInfo = new Implementation { Name = "fake-mcp-server", Version = "0.0.0" },
        Capabilities = new ServerCapabilities
        {
            Tools = new ToolsCapability(),
            Prompts = new PromptsCapability(),
        },
        Handlers = new McpServerHandlers
        {
            ListToolsHandler = HandleListTools,
            CallToolHandler = HandleCallTool,
            ListPromptsHandler = HandleListPrompts,
            GetPromptHandler = HandleGetPrompt,
        },
    };

    private static ValueTask<ListToolsResult> HandleListTools(
        RequestContext<ListToolsRequestParams> _,
        CancellationToken __) =>
        new(new ListToolsResult
        {
            Tools =
            [
                new Tool { Name = "read_file", Description = "Read a file." },
                new Tool { Name = "write_file", Description = "Write a file." },
            ],
        });

    private ValueTask<CallToolResult> HandleCallTool(
        RequestContext<CallToolRequestParams> ctx,
        CancellationToken _)
    {
        _receivedToolCalls.Add(ctx.Params!);
        if (_toolResults.Reader.TryRead(out var queued))
        {
            return new ValueTask<CallToolResult>(queued);
        }

        return new ValueTask<CallToolResult>(new CallToolResult
        {
            Content = [new TextContentBlock { Text = $"called:{ctx.Params!.Name}" }],
        });
    }

    private static ValueTask<ListPromptsResult> HandleListPrompts(
        RequestContext<ListPromptsRequestParams> _,
        CancellationToken __) =>
        new(new ListPromptsResult
        {
            Prompts = [new Prompt { Name = "onboard" }],
        });

    private ValueTask<GetPromptResult> HandleGetPrompt(
        RequestContext<GetPromptRequestParams> ctx,
        CancellationToken _)
    {
        _receivedPromptGets.Add(ctx.Params!);
        if (_promptResults.Reader.TryRead(out var queued))
        {
            return new ValueTask<GetPromptResult>(queued);
        }

        return new ValueTask<GetPromptResult>(new GetPromptResult
        {
            Messages =
            [
                new PromptMessage
                {
                    Role = Role.Assistant,
                    Content = new TextContentBlock { Text = "welcome" },
                },
            ],
        });
    }

    /// <summary>Cancels the run loop and completes the pipes.</summary>
    public async ValueTask DisposeAsync()
    {
        if (_cts is not null)
        {
            await _cts.CancelAsync().ConfigureAwait(false);
        }

        if (_runTask is not null)
        {
            try
            {
                await _runTask.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // Expected on shutdown.
            }
        }

        if (_server is not null)
        {
            await _server.DisposeAsync().ConfigureAwait(false);
        }

        _cts?.Dispose();

        _fromProxy?.Reader.Complete();
        _fromProxy?.Writer.Complete();
        _toProxy?.Reader.Complete();
        _toProxy?.Writer.Complete();
    }
}
