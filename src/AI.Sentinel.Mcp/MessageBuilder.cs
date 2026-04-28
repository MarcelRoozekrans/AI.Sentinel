using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.AI;
using ModelContextProtocol.Protocol;

namespace AI.Sentinel.Mcp;

/// <summary>Maps MCP protocol models to <see cref="ChatMessage"/> arrays for Sentinel scanning.</summary>
internal static class MessageBuilder
{
    private const string Separator = "\n---\n";
    private const string TruncationMarkerPrefix = " [truncated ";

    /// <summary>Builds the request-side scan payload for a <c>tools/call</c> invocation.</summary>
    /// <param name="req">The incoming tool-call request.</param>
    /// <param name="maxScanBytes">
    /// Upper bound (UTF-8 bytes) on the serialized-argument length that is forwarded to the
    /// detector pipeline. See <see cref="TruncateIfNeeded"/>.
    /// </param>
    public static ChatMessage[] BuildToolCallRequest(CallToolRequestParams req, int maxScanBytes)
    {
        var argsJson = SerializeArguments(req.Arguments, maxScanBytes);
        var text = $"tool:{req.Name} input:{argsJson}";
        return [new ChatMessage(ChatRole.User, text)];
    }

    /// <summary>Builds the response-side scan payload (request context + result text).</summary>
    /// <param name="req">The original tool-call request (for argument context).</param>
    /// <param name="result">The tool-call result to scan.</param>
    /// <param name="maxScanBytes">
    /// Upper bound (UTF-8 bytes) applied to both the serialized arguments and the flattened
    /// result text. See <see cref="TruncateIfNeeded"/>.
    /// </param>
    public static ChatMessage[] BuildToolCallResponse(
        CallToolRequestParams req, CallToolResult result, int maxScanBytes)
    {
        var argsJson = SerializeArguments(req.Arguments, maxScanBytes);
        var requestText = $"tool:{req.Name} input:{argsJson}";
        var responseText = ExtractScannableText(result.Content, maxScanBytes);

        if (string.IsNullOrEmpty(responseText))
        {
            return [new ChatMessage(ChatRole.User, requestText)];
        }

        return
        [
            new ChatMessage(ChatRole.User,      requestText),
            new ChatMessage(ChatRole.Assistant, responseText),
        ];
    }

    /// <summary>Builds a single tool-output <see cref="ChatMessage"/> representing one
    /// retrieved resource content item, for scanning via <see cref="SentinelPipeline"/>.</summary>
    /// <remarks>
    /// Resource bodies arrive already-typed as text (<see cref="ModelContextProtocol.Protocol.TextResourceContents"/>);
    /// the caller is responsible for filtering out non-text (blob) variants and applying any
    /// MIME allowlist / oversize gates before invoking this helper. Truncation has already
    /// been applied by the interceptor against the UTF-8 byte budget.
    /// </remarks>
    public static ChatMessage BuildResourceRead(string text)
        => new(ChatRole.Tool, text);

    /// <summary>Builds the scan payload for a <c>prompts/get</c> response.</summary>
    /// <param name="result">The prompt result to scan.</param>
    /// <param name="maxScanBytes">
    /// Upper bound (UTF-8 bytes) on the flattened prompt-message text.
    /// See <see cref="TruncateIfNeeded"/>.
    /// </param>
    public static ChatMessage[] BuildPromptGetResponse(
        GetPromptResult result, int maxScanBytes)
    {
        var flattened = FlattenPromptMessages(result.Messages, maxScanBytes);
        if (string.IsNullOrEmpty(flattened))
        {
            return [];
        }
        return [new ChatMessage(ChatRole.Assistant, flattened)];
    }

    private static string SerializeArguments(IDictionary<string, JsonElement>? args, int maxScanBytes)
    {
        if (args is null || args.Count == 0) return "{}";
        var json = JsonSerializer.Serialize(args, McpJsonContext.Default.IDictionaryStringJsonElement);
        return TruncateIfNeeded(json, maxScanBytes);
    }

    private static string ExtractScannableText(IList<ContentBlock>? blocks, int maxScanBytes)
    {
        if (blocks is null || blocks.Count == 0) return string.Empty;

        var sb = new StringBuilder();
        var first = true;
        foreach (var block in blocks)
        {
            if (block is TextContentBlock text && !string.IsNullOrEmpty(text.Text))
            {
                if (!first) sb.Append(Separator);
                sb.Append(text.Text);
                first = false;
            }
        }

        return TruncateIfNeeded(sb.ToString(), maxScanBytes);
    }

    private static string FlattenPromptMessages(IList<PromptMessage>? messages, int maxScanBytes)
    {
        if (messages is null || messages.Count == 0) return string.Empty;

        var sb = new StringBuilder();
        var first = true;
        foreach (var msg in messages)
        {
            if (msg.Content is TextContentBlock text && !string.IsNullOrEmpty(text.Text))
            {
                if (!first) sb.Append(Separator);
                sb.Append(text.Text);
                first = false;
            }
        }

        return TruncateIfNeeded(sb.ToString(), maxScanBytes);
    }

    /// <summary>Truncates <paramref name="text"/> so its UTF-8 byte length is at most
    /// <paramref name="maxScanBytes"/>.</summary>
    /// <remarks>
    /// The cap is enforced against <see cref="Encoding.UTF8.GetByteCount(string)"/> as the
    /// <c>SENTINEL_MCP_MAX_SCAN_BYTES</c> environment variable name implies. For ASCII input
    /// this is identical to char-count; for multi-byte content (emoji, CJK, etc.) the cap
    /// fires sooner. The trailing marker reports removed UTF-8 bytes.
    /// </remarks>
    internal static string TruncateIfNeeded(string text, int maxScanBytes)
    {
        var totalBytes = Encoding.UTF8.GetByteCount(text);
        if (totalBytes <= maxScanBytes) return text;

        // Slice on a UTF-16 code-unit boundary that keeps the resulting prefix at or below
        // the byte budget. We walk text spans whose byte counts we can compute cheaply, and
        // step back one char at a time if the chosen split lands in the middle of a
        // surrogate pair.
        var charCount = ApproximateCharLimit(text, maxScanBytes);
        while (charCount > 0 && Encoding.UTF8.GetByteCount(text.AsSpan(0, charCount)) > maxScanBytes)
        {
            charCount--;
        }
        // Avoid splitting a surrogate pair (would corrupt the unicorn 🦄 etc.).
        if (charCount > 0 && charCount < text.Length
            && char.IsHighSurrogate(text[charCount - 1])
            && char.IsLowSurrogate(text[charCount]))
        {
            charCount--;
        }

        var truncated = text[..charCount];
        var removed = totalBytes - Encoding.UTF8.GetByteCount(truncated);
        return $"{truncated}{TruncationMarkerPrefix}{removed} bytes]";
    }

    /// <summary>Initial guess for the char-count whose UTF-8 encoding fits in
    /// <paramref name="maxScanBytes"/>. Always &lt;= <c>text.Length</c>.</summary>
    private static int ApproximateCharLimit(string text, int maxScanBytes)
    {
        // Every UTF-16 code unit is ≥ 1 UTF-8 byte, so maxScanBytes is a safe upper bound
        // on the char count. Min with text.Length to skip pointless walk-back iterations.
        return maxScanBytes < text.Length ? maxScanBytes : text.Length;
    }
}
