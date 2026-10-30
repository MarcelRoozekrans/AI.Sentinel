using System.Globalization;
using AI.Sentinel.ClaudeCode;
using AI.Sentinel.Domain;
using AI.Sentinel.Mcp.Logging;
using AI.Sentinel.Redaction;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

namespace AI.Sentinel.Mcp;

/// <summary>
/// Intercepts <c>resources/read</c> responses, scans matching content items via
/// <see cref="SentinelPipeline.ScanMessagesAsync"/>.
/// </summary>
/// <remarks>
/// <para>
/// Only <see cref="TextResourceContents"/> entries whose <see cref="ResourceContents.MimeType"/>
/// matches the configured allowlist (<c>SENTINEL_MCP_SCAN_MIMES</c>, comma-separated; suffix
/// wildcards via trailing <c>/</c> are supported) are scanned. <see cref="BlobResourceContents"/>
/// and other MIME types are forwarded verbatim. Each item is scanned on its own against
/// <see cref="SentinelOptions.MaxScanBytes"/>, which the proxy sets from <c>SENTINEL_MCP_MAX_SCAN_BYTES</c> (default
/// 262 144, shared with tool calls and prompts). An item over it is scanned up to the budget and the pipeline reports
/// <c>SEC-00</c>, which blocks the read under the default <c>OnCritical</c> (#439); 4.1 skipped such an item unscanned.
/// </para>
/// <para>
/// Authorization is intentionally not consulted here — resources are data, not actions.
/// Detection-pipeline failures fail open (logged, forwarded). A <see cref="SentinelError.ThreatDetected"/>
/// blocks via <see cref="McpProtocolException"/> with <see cref="McpErrorCode.InternalError"/>,
/// matching <see cref="ToolCallInterceptor"/> and <see cref="PromptGetInterceptor"/>.
/// </para>
/// <para>
/// When a <see cref="PlaceholderStore"/> is supplied, the allowlisted text items are redacted whole, in place, before
/// they reach the agent, and each is scanned as redacted. Blob and non-allowlisted items are forwarded as in 3.0.
/// </para>
/// </remarks>
internal static class ResourceReadInterceptor
{
    // Default allowlist: text/* family + common structured-text MIME types.
    private static readonly string[] DefaultMimes =
    [
        "text/", "application/json", "application/xml", "application/yaml",
    ];

    public static McpRequestFilter<ReadResourceRequestParams, ReadResourceResult> Create(
        SentinelPipeline pipeline,
        SessionId? sessionId = null,
        PlaceholderStore? placeholders = null)
    {
        ArgumentNullException.ThrowIfNull(pipeline);

        var allowedMimes = ParseMimeAllowlist();

        return next => (ctx, ct) => InvokeAsync(pipeline, allowedMimes, sessionId, placeholders, next, ctx, ct);
    }

    private static async ValueTask<ReadResourceResult> InvokeAsync(
        SentinelPipeline pipeline,
        HashSet<string> allowedMimes,
        SessionId? sessionId,
        PlaceholderStore? placeholders,
        McpRequestHandler<ReadResourceRequestParams, ReadResourceResult> next,
        RequestContext<ReadResourceRequestParams> ctx,
        CancellationToken ct)
    {
        var req = ctx.Params ?? throw new McpProtocolException(
            "missing resources/read parameters", McpErrorCode.InvalidParams);

        var result = await next(ctx, ct).ConfigureAwait(false);

        if (result.Contents is null || result.Contents.Count == 0)
        {
            LogAllow(req.Uri, reason: "empty");
            return result;
        }

        var redactable = new List<TextResourceContents>();
        foreach (var content in result.Contents)
        {
            // Blob resources (images, binaries) are not scanned — log and continue.
            if (content is not TextResourceContents textContent)
            {
                LogSkipped(req.Uri, reason: "mime", content.MimeType ?? "(blob)");
                continue;
            }

            if (string.IsNullOrEmpty(textContent.Text))
            {
                continue;
            }

            if (!IsAllowedMime(textContent.MimeType, allowedMimes))
            {
                LogSkipped(req.Uri, reason: "mime", textContent.MimeType ?? "(none)");
                continue;
            }

            if (placeholders is not null)
            {
                redactable.Add(textContent);
                continue;
            }

            var scanError = await ScanSafelyAsync(pipeline, textContent.Text, req.Uri, sessionId, ct).ConfigureAwait(false);
            BlockIfThreat(req.Uri, scanError);
        }

        var (redacted, rateLimited) = placeholders is not null && redactable.Count > 0
            ? await RedactAsync(pipeline, placeholders, redactable, req.Uri, sessionId, ct).ConfigureAwait(false)
            : (0, false);

        LogAllow(req.Uri, reason: rateLimited ? "rate_limited" : null, redacted);
        return result;
    }

    /// <summary>
    /// Redacts and scans each item on its own, as 3.0 scanned them, so the items of one read neither add up to a
    /// burst of tool messages nor dilute each other. Every item is scanned before any is written back: a threat in
    /// any item blocks the read, and then nothing is written back or audited as redacted. Otherwise each item is
    /// written back and its redactions are audited. A pipeline failure on an item fails open for that item and logs
    /// only the exception type, because its message can carry the value. Returns the number of redacted occurrences
    /// and whether any scan was skipped by the rate limit.
    /// </summary>
    private static async ValueTask<(int Redacted, bool RateLimited)> RedactAsync(
        SentinelPipeline pipeline,
        PlaceholderStore placeholders,
        List<TextResourceContents> items,
        string uri,
        SessionId? sessionId,
        CancellationToken ct)
    {
        var scans = new List<(TextResourceContents Item, HostRedactionResult Scanned)>(items.Count);
        var rateLimited = false;
        foreach (var item in items)
        {
            HostRedactionResult scanned;
            try
            {
                scanned = await McpRedaction.RedactAndScanAsync(
                    pipeline, placeholders, context: [], [HostContent.FromText(item.Text)],
                    Microsoft.Extensions.AI.ChatRole.Tool, sessionId, ct).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                LogFailOpen(uri, ex.GetType().Name);
                continue;
            }

            BlockIfThreat(uri, scanned.Error);
            rateLimited |= scanned.Error is SentinelError.RateLimitExceeded;
            scans.Add((item, scanned));
        }

        var total = 0;
        foreach (var (item, scanned) in scans)
        {
            McpRedaction.WriteBack(scanned, [redacted => item.Text = redacted.Text!], placeholders);
            if (!scanned.Redacted) continue;

            await AppendRedactionsSafelyAsync(pipeline, scanned, uri, ct).ConfigureAwait(false);
            total += McpRedaction.TotalRedacted(scanned);
        }
        return (total, rateLimited);
    }

    private static async ValueTask AppendRedactionsSafelyAsync(
        SentinelPipeline pipeline, HostRedactionResult scanned, string uri, CancellationToken ct)
    {
        try
        {
            await pipeline.AppendRedactionsAsync(scanned, scanned.SessionId, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            StderrLogger.Log(new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["event"] = "resources_read",
                ["action"] = "audit_failed",
                ["uri"] = uri,
                ["error"] = ex.GetType().Name,
            });
        }
    }

    private static void BlockIfThreat(string uri, SentinelError? error)
    {
        if (error is not SentinelError.ThreatDetected threat) return;

        LogBlock(uri, threat);
        throw new McpProtocolException(
            $"Blocked by AI.Sentinel: {threat.Result.DetectorId.Value} {threat.Result.Severity}: {threat.Result.Reason}",
            McpErrorCode.InternalError);
    }

    private static async ValueTask<SentinelError?> ScanSafelyAsync(
        SentinelPipeline pipeline, string text, string uri, SessionId? sessionId, CancellationToken ct)
    {
        try
        {
            return await pipeline.ScanMessagesAsync(
                [MessageBuilder.BuildResourceRead(text)], ct: ct, sessionId: sessionId).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            LogFailOpen(uri, ex.GetType().Name);
            return null;
        }
    }

    /// <summary>Logs the exception type only: a message can carry the scanned text.</summary>
    private static void LogFailOpen(string uri, string error) =>
        StderrLogger.Log(new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["event"] = "resources_read",
            ["action"] = "fail_open",
            ["uri"] = uri,
            ["error"] = error,
        });

    private static void LogAllow(string uri, string? reason, int redacted = 0)
    {
        var fields = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["event"] = "resources_read",
            ["action"] = "allow",
            ["uri"] = uri,
        };
        if (!string.IsNullOrEmpty(reason)) fields["reason"] = reason;
        if (redacted > 0) fields["redacted"] = redacted.ToString(CultureInfo.InvariantCulture);
        StderrLogger.Log(fields);
    }

    private static void LogSkipped(string uri, string reason, string mime) =>
        StderrLogger.Log(new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["event"] = "resources_read",
            ["action"] = "skipped",
            ["reason"] = reason,
            ["uri"] = uri,
            ["mime"] = mime,
        });

    private static void LogBlock(string uri, SentinelError.ThreatDetected threat) =>
        StderrLogger.Log(new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["event"] = "resources_read",
            ["action"] = "block",
            ["uri"] = uri,
            ["detector"] = threat.Result.DetectorId.Value,
            ["severity"] = threat.Result.Severity.ToString(),
        });

    /// <summary>The MIME allowlist from <c>SENTINEL_MCP_SCAN_MIMES</c>, or the default text/JSON/XML/YAML set.</summary>
    internal static HashSet<string> ParseMimeAllowlist()
    {
        var raw = Environment.GetEnvironmentVariable("SENTINEL_MCP_SCAN_MIMES");
        if (string.IsNullOrWhiteSpace(raw))
        {
            return new HashSet<string>(DefaultMimes, StringComparer.OrdinalIgnoreCase);
        }

        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var m in raw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            set.Add(m);
        }
        return set;
    }

    internal static bool IsAllowedMime(string? mime, HashSet<string> allowed)
    {
        if (string.IsNullOrWhiteSpace(mime)) return false;
        foreach (var pattern in allowed)
        {
            if (pattern.EndsWith('/'))
            {
                if (mime.StartsWith(pattern, StringComparison.OrdinalIgnoreCase)) return true;
            }
            else if (string.Equals(pattern, mime, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }
        return false;
    }
}
