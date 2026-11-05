using System.Globalization;
using AI.Sentinel.Domain;
using AI.Sentinel.Redaction;
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
/// A pipeline that throws fails closed, matching <see cref="ToolCallInterceptor"/>: the exception type goes to
/// stderr, never its message, and the call is blocked with <see cref="McpFailClosed.Block"/>. Cancellation
/// propagates.
/// A block throws <see cref="McpProtocolException"/>, not the base <see cref="McpException"/>, because the SDK's
/// request pipeline silently wraps a plain <c>McpException</c> into the return result, whereas
/// <see cref="McpProtocolException"/> escapes as a real JSON-RPC error.
/// When a <see cref="PlaceholderStore"/> is supplied, message text and allowlisted embedded text resources are
/// redacted before they reach the agent, and the redacted messages are what the scan judges.
/// </remarks>
internal static class PromptGetInterceptor
{
    public static McpRequestFilter<GetPromptRequestParams, GetPromptResult> Create(
        SentinelPipeline pipeline,
        TextWriter stderr,
        SessionId? sessionId = null,
        PlaceholderStore? placeholders = null)
    {
        ArgumentNullException.ThrowIfNull(pipeline);
        ArgumentNullException.ThrowIfNull(stderr);

        if (placeholders is not null)
        {
            var allowedMimes = ResourceReadInterceptor.ParseMimeAllowlist();
            return next => (ctx, ct) => InvokeRedactingAsync(pipeline, stderr, sessionId, placeholders, allowedMimes, next, ctx, ct);
        }

        return next => (ctx, ct) => InvokeAsync(pipeline, stderr, sessionId, next, ctx, ct);
    }

    /// <summary>
    /// Redacts the prompt in place and scans the redacted copy. A threat blocks and nothing is written back or
    /// audited as redacted. A pipeline failure fails closed and logs only the exception type, because its message can
    /// carry the value.
    /// </summary>
    private static async ValueTask<GetPromptResult> InvokeRedactingAsync(
        SentinelPipeline pipeline,
        TextWriter stderr,
        SessionId? sessionId,
        PlaceholderStore placeholders,
        HashSet<string> allowedMimes,
        McpRequestHandler<GetPromptRequestParams, GetPromptResult> next,
        RequestContext<GetPromptRequestParams> ctx,
        CancellationToken ct)
    {
        var req = ctx.Params ?? throw new McpProtocolException(
            "missing prompts/get parameters", McpErrorCode.InvalidParams);

        // No pre-scan — prompts/get request is metadata (name + args), not user content.
        var result = await next(ctx, ct).ConfigureAwait(false);

        // The blocks are the result's own, deserialized fresh for this request, so they are rewritten in place.
        var (content, apply) = MessageBuilder.CollectRedactable(BlocksOf(result), allowedMimes);
        if (content.Count == 0)
        {
            await stderr.WriteLineAsync(
                $"[sentinel-mcp] event=prompts/get decision=Allow prompt={req.Name} reason=empty"
            ).ConfigureAwait(false);
            return result;
        }

        HostRedactionResult scanned;
        try
        {
            scanned = await McpRedaction.RedactAndScanAsync(
                pipeline, placeholders, context: [], content,
                Microsoft.Extensions.AI.ChatRole.Assistant, sessionId, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            throw await FailClosedAsync(ex, req.Name, stderr).ConfigureAwait(false);
        }

        await BlockIfThreatAsync(scanned.Error, req.Name, stderr).ConfigureAwait(false);

        McpRedaction.WriteBack(scanned, apply, placeholders);
        var redactedSuffix = string.Empty;
        if (scanned.Redacted)
        {
            await AppendRedactionsSafelyAsync(pipeline, scanned, stderr, ct).ConfigureAwait(false);
            redactedSuffix = " redacted=" + McpRedaction.TotalRedacted(scanned).ToString(CultureInfo.InvariantCulture);
        }

        if (scanned.Error is SentinelError.RateLimitExceeded)
        {
            redactedSuffix += " reason=rate_limited";
        }

        await stderr.WriteLineAsync(
            $"[sentinel-mcp] event=prompts/get decision=Allow prompt={req.Name}{redactedSuffix}"
        ).ConfigureAwait(false);
        return result;
    }

    private static async ValueTask<GetPromptResult> InvokeAsync(
        SentinelPipeline pipeline,
        TextWriter stderr,
        SessionId? sessionId,
        McpRequestHandler<GetPromptRequestParams, GetPromptResult> next,
        RequestContext<GetPromptRequestParams> ctx,
        CancellationToken ct)
    {
        var req = ctx.Params ?? throw new McpProtocolException(
            "missing prompts/get parameters", McpErrorCode.InvalidParams);

        // No pre-scan — prompts/get request is metadata (name + args), not user content.
        var result = await next(ctx, ct).ConfigureAwait(false);

        var responseMessages = MessageBuilder.BuildPromptGetResponse(result);
        if (responseMessages.Length == 0)
        {
            await stderr.WriteLineAsync(
                $"[sentinel-mcp] event=prompts/get decision=Allow prompt={req.Name} reason=empty"
            ).ConfigureAwait(false);
            return result;
        }

        var postError = await ScanAsync(pipeline, responseMessages, req.Name, stderr, sessionId, ct).ConfigureAwait(false);
        await BlockIfThreatAsync(postError, req.Name, stderr).ConfigureAwait(false);

        await stderr.WriteLineAsync(
            $"[sentinel-mcp] event=prompts/get decision=Allow prompt={req.Name}"
        ).ConfigureAwait(false);
        return result;
    }

    private static List<ContentBlock> BlocksOf(GetPromptResult result)
    {
        var blocks = new List<ContentBlock>();
        if (result.Messages is null) return blocks;

        foreach (var message in result.Messages)
        {
            if (message.Content is not null) blocks.Add(message.Content);
        }
        return blocks;
    }

    private static async ValueTask AppendRedactionsSafelyAsync(
        SentinelPipeline pipeline, HostRedactionResult scanned, TextWriter stderr, CancellationToken ct)
    {
        try
        {
            await pipeline.AppendRedactionsAsync(scanned, scanned.SessionId, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            await stderr.WriteLineAsync(
                $"[sentinel-mcp] event=prompts/get decision=AuditFailed phase=redaction reason={ex.GetType().Name}"
            ).ConfigureAwait(false);
        }
    }

    private static async ValueTask BlockIfThreatAsync(SentinelError? error, string promptName, TextWriter stderr)
    {
        if (error is not SentinelError.ThreatDetected threat) return;

        await stderr.WriteLineAsync(
            $"[sentinel-mcp] event=prompts/get decision=Block prompt={promptName} detector={threat.Result.DetectorId.Value} severity={threat.Result.Severity} phase=response"
        ).ConfigureAwait(false);
        throw new McpProtocolException(
            $"Blocked by AI.Sentinel: {threat.Result.DetectorId.Value} {threat.Result.Severity}: {threat.Result.Reason}",
            McpErrorCode.InternalError);
    }

    private static async ValueTask<SentinelError?> ScanAsync(
        SentinelPipeline pipeline,
        Microsoft.Extensions.AI.ChatMessage[] messages,
        string promptName,
        TextWriter stderr,
        SessionId? sessionId,
        CancellationToken ct)
    {
        try
        {
            return await pipeline.ScanMessagesAsync(messages, ct: ct, sessionId: sessionId).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            throw await FailClosedAsync(ex, promptName, stderr).ConfigureAwait(false);
        }
    }

    private static async ValueTask<McpProtocolException> FailClosedAsync(Exception ex, string promptName, TextWriter stderr)
    {
        await stderr.WriteLineAsync(
            $"[sentinel-mcp] event=prompts/get decision=FailClosed prompt={promptName} phase=response reason={ex.GetType().Name}"
        ).ConfigureAwait(false);
        return McpFailClosed.Block(ex);
    }
}
