using AI.Sentinel.ClaudeCode;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

namespace AI.Sentinel.Mcp;

/// <summary>
/// Intercepts <c>prompts/get</c> requests. Forwards the request to the target unscanned
/// (<c>prompts/get</c> params are metadata only — there's no user content in them). Scans the
/// response: if the target returns adversarial content (e.g., injection payloads
/// embedded in the prompt), blocks with <see cref="McpProtocolException"/>.
/// </summary>
/// <remarks>
/// Sentinel exceptions are caught and fail-open to stderr, matching
/// <see cref="ToolCallInterceptor"/>. Throws <see cref="McpProtocolException"/> on block
/// (not the base <see cref="McpException"/>) — the SDK's request pipeline silently wraps
/// plain <c>McpException</c> into the return result, whereas <see cref="McpProtocolException"/>
/// escapes as a real JSON-RPC error.
/// </remarks>
internal static class PromptGetInterceptor
{
    public static McpRequestFilter<GetPromptRequestParams, GetPromptResult> Create(
        SentinelPipeline pipeline,
        int maxScanBytes,
        TextWriter stderr)
    {
        ArgumentNullException.ThrowIfNull(pipeline);
        ArgumentNullException.ThrowIfNull(stderr);

        return next => (ctx, ct) => InvokeAsync(pipeline, maxScanBytes, stderr, next, ctx, ct);
    }

    private static async ValueTask<GetPromptResult> InvokeAsync(
        SentinelPipeline pipeline,
        int maxScanBytes,
        TextWriter stderr,
        McpRequestHandler<GetPromptRequestParams, GetPromptResult> next,
        RequestContext<GetPromptRequestParams> ctx,
        CancellationToken ct)
    {
        var req = ctx.Params ?? throw new McpProtocolException(
            "missing prompts/get parameters", McpErrorCode.InvalidParams);

        // No pre-scan — prompts/get request is metadata (name + args), not user content.
        var result = await next(ctx, ct).ConfigureAwait(false);

        var responseMessages = MessageBuilder.BuildPromptGetResponse(result, maxScanBytes);
        if (responseMessages.Length == 0)
        {
            await stderr.WriteLineAsync(
                $"[sentinel-mcp] event=prompts/get decision=Allow prompt={req.Name} reason=empty"
            ).ConfigureAwait(false);
            return result;
        }

        var postError = await ScanSafelyAsync(pipeline, responseMessages, stderr, ct).ConfigureAwait(false);
        if (postError is SentinelError.ThreatDetected threat)
        {
            await stderr.WriteLineAsync(
                $"[sentinel-mcp] event=prompts/get decision=Block prompt={req.Name} detector={threat.Result.DetectorId.Value} severity={threat.Result.Severity} phase=response"
            ).ConfigureAwait(false);
            throw new McpProtocolException(
                $"Blocked by AI.Sentinel: {threat.Result.DetectorId.Value} {threat.Result.Severity}: {threat.Result.Reason}",
                McpErrorCode.InternalError);
        }

        await stderr.WriteLineAsync(
            $"[sentinel-mcp] event=prompts/get decision=Allow prompt={req.Name}"
        ).ConfigureAwait(false);
        return result;
    }

    private static async ValueTask<SentinelError?> ScanSafelyAsync(
        SentinelPipeline pipeline,
        Microsoft.Extensions.AI.ChatMessage[] messages,
        TextWriter stderr,
        CancellationToken ct)
    {
        try
        {
            return await pipeline.ScanMessagesAsync(messages, ct: ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            await stderr.WriteLineAsync(
                $"[sentinel-mcp] event=prompts/get decision=FailOpen phase=response reason={ex.GetType().Name}:{ex.Message}"
            ).ConfigureAwait(false);
            return null;
        }
    }
}
