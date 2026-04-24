using AI.Sentinel.ClaudeCode;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

namespace AI.Sentinel.Mcp;

/// <summary>
/// Builds the <see cref="McpRequestFilter{TParams,TResult}"/> that pre-scans
/// <c>tools/call</c> arguments and post-scans the result via
/// <see cref="SentinelPipeline.ScanMessagesAsync"/>.
/// </summary>
/// <remarks>
/// Fail-open semantics for pipeline bugs: any exception out of
/// <see cref="SentinelPipeline.ScanMessagesAsync"/> is logged to <c>stderr</c>
/// and the call forwards. Only a <see cref="SentinelError.ThreatDetected"/>
/// yields a block. Blocks raise <see cref="McpProtocolException"/> with
/// <see cref="McpErrorCode.InternalError"/> so the SDK emits a JSON-RPC error
/// (plain <see cref="McpException"/> would be swallowed by the tool-call
/// wrapper into a <see cref="CallToolResult"/> with <c>IsError=true</c>).
/// </remarks>
internal static class ToolCallInterceptor
{
    public static McpRequestFilter<CallToolRequestParams, CallToolResult> Create(
        SentinelPipeline pipeline,
        int maxScanBytes,
        TextWriter stderr) =>
        next => (ctx, ct) => InvokeAsync(pipeline, maxScanBytes, stderr, next, ctx, ct);

    private static async ValueTask<CallToolResult> InvokeAsync(
        SentinelPipeline pipeline,
        int maxScanBytes,
        TextWriter stderr,
        McpRequestHandler<CallToolRequestParams, CallToolResult> next,
        RequestContext<CallToolRequestParams> ctx,
        CancellationToken ct)
    {
        var req = ctx.Params ?? throw new McpProtocolException(
            "missing tool call parameters", McpErrorCode.InvalidParams);

        var requestMessages = MessageBuilder.BuildToolCallRequest(req);
        var preError = await ScanSafelyAsync(pipeline, requestMessages, stderr, phase: "pre", ct).ConfigureAwait(false);
        await BlockIfThreatAsync(preError, req.Name, stderr, phase: "request").ConfigureAwait(false);

        var result = await next(ctx, ct).ConfigureAwait(false);

        var responseMessages = MessageBuilder.BuildToolCallResponse(req, result, maxScanBytes);
        var postError = await ScanSafelyAsync(pipeline, responseMessages, stderr, phase: "post", ct).ConfigureAwait(false);
        await BlockIfThreatAsync(postError, req.Name, stderr, phase: "response").ConfigureAwait(false);

        await stderr.WriteLineAsync(
            $"[sentinel-mcp] event=tools/call decision=Allow tool={req.Name}"
        ).ConfigureAwait(false);
        return result;
    }

    private static async ValueTask<SentinelError?> ScanSafelyAsync(
        SentinelPipeline pipeline,
        Microsoft.Extensions.AI.ChatMessage[] messages,
        TextWriter stderr,
        string phase,
        CancellationToken ct)
    {
        try
        {
            return await pipeline.ScanMessagesAsync(messages, ct: ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            await stderr.WriteLineAsync(
                $"[sentinel-mcp] event=tools/call decision=FailOpen phase={phase} reason={ex.GetType().Name}:{ex.Message}"
            ).ConfigureAwait(false);
            return null;
        }
    }

    private static async ValueTask BlockIfThreatAsync(
        SentinelError? error, string toolName, TextWriter stderr, string phase)
    {
        if (error is not SentinelError.ThreatDetected threat) return;

        await stderr.WriteLineAsync(
            $"[sentinel-mcp] event=tools/call decision=Block tool={toolName} detector={threat.Result.DetectorId} severity={threat.Result.Severity} phase={phase}"
        ).ConfigureAwait(false);

        throw new McpProtocolException(
            $"Blocked by AI.Sentinel: {threat.Result.DetectorId} {threat.Result.Severity}: {threat.Result.Reason}",
            McpErrorCode.InternalError);
    }
}
