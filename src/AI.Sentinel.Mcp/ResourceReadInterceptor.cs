using System.Globalization;
using System.Text;
using AI.Sentinel.ClaudeCode;
using AI.Sentinel.Mcp.Logging;
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
/// and other MIME types are forwarded verbatim. Per-content-item UTF-8 byte budgets are gated
/// by <c>SENTINEL_MCP_MAX_SCAN_BYTES</c> (default 65 536); oversize text items are skipped with
/// a structured stderr log line.
/// </para>
/// <para>
/// Authorization is intentionally not consulted here — resources are data, not actions.
/// Detection-pipeline failures fail open (logged, forwarded). A <see cref="SentinelError.ThreatDetected"/>
/// blocks via <see cref="McpProtocolException"/> with <see cref="McpErrorCode.InternalError"/>,
/// matching <see cref="ToolCallInterceptor"/> and <see cref="PromptGetInterceptor"/>.
/// </para>
/// </remarks>
internal static class ResourceReadInterceptor
{
    // Default allowlist: text/* family + common structured-text MIME types.
    private static readonly string[] DefaultMimes =
    [
        "text/", "application/json", "application/xml", "application/yaml",
    ];

    private const int DefaultMaxScanBytes = 65_536;

    public static McpRequestFilter<ReadResourceRequestParams, ReadResourceResult> Create(
        SentinelPipeline pipeline)
    {
        ArgumentNullException.ThrowIfNull(pipeline);

        var allowedMimes = ParseMimeAllowlist();
        var maxBytes = ParseMaxBytes();

        return next => (ctx, ct) => InvokeAsync(pipeline, allowedMimes, maxBytes, next, ctx, ct);
    }

    private static async ValueTask<ReadResourceResult> InvokeAsync(
        SentinelPipeline pipeline,
        HashSet<string> allowedMimes,
        int maxBytes,
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

            var byteCount = Encoding.UTF8.GetByteCount(textContent.Text);
            if (byteCount > maxBytes)
            {
                LogOversize(req.Uri, byteCount, maxBytes);
                continue;
            }

            var scanError = await ScanSafelyAsync(pipeline, textContent.Text, req.Uri, ct).ConfigureAwait(false);
            if (scanError is SentinelError.ThreatDetected threat)
            {
                LogBlock(req.Uri, threat);
                throw new McpProtocolException(
                    $"Blocked by AI.Sentinel: {threat.Result.DetectorId} {threat.Result.Severity}: {threat.Result.Reason}",
                    McpErrorCode.InternalError);
            }
        }

        LogAllow(req.Uri, reason: null);
        return result;
    }

    private static async ValueTask<SentinelError?> ScanSafelyAsync(
        SentinelPipeline pipeline, string text, string uri, CancellationToken ct)
    {
        try
        {
            return await pipeline.ScanMessagesAsync(
                [MessageBuilder.BuildResourceRead(text)], ct: ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            StderrLogger.Log(new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["event"]    = "resources_read",
                ["action"]   = "fail_open",
                ["uri"]      = uri,
                ["error"]    = ex.GetType().Name,
                ["message"]  = ex.Message,
            });
            return null;
        }
    }

    private static void LogAllow(string uri, string? reason)
    {
        var fields = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["event"]  = "resources_read",
            ["action"] = "allow",
            ["uri"]    = uri,
        };
        if (!string.IsNullOrEmpty(reason)) fields["reason"] = reason;
        StderrLogger.Log(fields);
    }

    private static void LogSkipped(string uri, string reason, string mime) =>
        StderrLogger.Log(new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["event"]  = "resources_read",
            ["action"] = "skipped",
            ["reason"] = reason,
            ["uri"]    = uri,
            ["mime"]   = mime,
        });

    private static void LogOversize(string uri, int bytes, int maxBytes) =>
        StderrLogger.Log(new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["event"]    = "resources_read",
            ["action"]   = "skipped",
            ["reason"]   = "oversize",
            ["uri"]      = uri,
            ["bytes"]    = bytes.ToString(CultureInfo.InvariantCulture),
            ["max"]      = maxBytes.ToString(CultureInfo.InvariantCulture),
        });

    private static void LogBlock(string uri, SentinelError.ThreatDetected threat) =>
        StderrLogger.Log(new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["event"]    = "resources_read",
            ["action"]   = "block",
            ["uri"]      = uri,
            ["detector"] = threat.Result.DetectorId.ToString(),
            ["severity"] = threat.Result.Severity.ToString(),
        });

    private static HashSet<string> ParseMimeAllowlist()
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

    private static int ParseMaxBytes()
    {
        var raw = Environment.GetEnvironmentVariable("SENTINEL_MCP_MAX_SCAN_BYTES");
        return int.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var v) && v > 0
            ? v
            : DefaultMaxScanBytes;
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
