using AI.Sentinel.Domain;
using AI.Sentinel.Redaction;
using Microsoft.Extensions.AI;

namespace AI.Sentinel.Mcp;

/// <summary>
/// The redacting scan the three interceptors share: content on its way to the agent is redacted, the redacted copy
/// is scanned, and only content that is delivered is written back, registered in the proxy's
/// <see cref="PlaceholderStore"/> and audited as <c>REDACTED</c>.
/// </summary>
internal static class McpRedaction
{
    /// <summary>Redacts <paramref name="content"/> and scans it together with <paramref name="context"/>, which is
    /// redacted in the scan copy only. Every item is redacted whole; the scan of <paramref name="content"/> is cut to
    /// <see cref="SentinelOptions.MaxScanBytes"/> and reports content over it as <c>SEC-00</c>. Placeholders the proxy
    /// minted earlier are neither flagged nor redacted again.</summary>
    public static ValueTask<HostRedactionResult> RedactAndScanAsync(
        SentinelPipeline pipeline,
        PlaceholderStore placeholders,
        IReadOnlyList<ChatMessage> context,
        IReadOnlyList<HostContent> content,
        ChatRole contentRole,
        SessionId? sessionId,
        CancellationToken ct)
        => pipeline.RedactAndScanAsync(
            new HostRedactionRequest
            {
                Context = context,
                Content = content,
                ContentRole = contentRole,
                KnownPlaceholders = placeholders.KnownTokens(),
            },
            sessionId,
            ct);

    /// <summary>Writes the redacted content back with <paramref name="apply"/> and registers the placeholders it
    /// minted. Call it only when the content is delivered. Does nothing when nothing was redacted, so the result
    /// stays as the target sent it.</summary>
    public static void WriteBack(HostRedactionResult result, IReadOnlyList<Action<HostContent>> apply, PlaceholderStore placeholders)
    {
        if (!result.Redacted)
        {
            return;
        }

        for (var i = 0; i < apply.Count; i++)
        {
            apply[i](result.Content[i]);
        }

        placeholders.Register(result.Minted);
    }

    /// <summary>The total number of redacted occurrences, for the stderr line.</summary>
    public static int TotalRedacted(HostRedactionResult result)
    {
        var total = 0;
        foreach (var count in result.RedactedByType.Values)
        {
            total += count;
        }
        return total;
    }
}
