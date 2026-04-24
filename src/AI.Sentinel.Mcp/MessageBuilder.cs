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
    /// Upper bound on the serialized-argument length that is forwarded to the detector
    /// pipeline. See <see cref="TruncateIfNeeded"/> for the char-vs-byte caveat.
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
    /// Upper bound applied to both the serialized arguments and the flattened result text.
    /// See <see cref="TruncateIfNeeded"/> for the char-vs-byte caveat.
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

    /// <summary>Builds the scan payload for a <c>prompts/get</c> response.</summary>
    /// <param name="result">The prompt result to scan.</param>
    /// <param name="maxScanBytes">
    /// Upper bound on the flattened prompt-message text.
    /// See <see cref="TruncateIfNeeded"/> for the char-vs-byte caveat.
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

    /// <summary>Truncates <paramref name="text"/> to at most <paramref name="maxScanBytes"/> characters.</summary>
    /// <remarks>
    /// Despite the parameter name, the cap is currently enforced against
    /// <see cref="string.Length"/> (UTF-16 char count), not the UTF-8 byte count implied by
    /// the <c>SENTINEL_MCP_MAX_SCAN_BYTES</c> environment variable. For ASCII input the two
    /// are identical; for multi-byte UTF-8 content the effective byte cap may be 2-4x the
    /// configured value. A future change may switch to <c>Encoding.UTF8.GetByteCount</c> for
    /// a true byte-accurate bound.
    /// </remarks>
    private static string TruncateIfNeeded(string text, int maxScanBytes)
    {
        if (text.Length <= maxScanBytes) return text;
        var truncated = text[..maxScanBytes];
        var removed = text.Length - maxScanBytes;
        return $"{truncated}{TruncationMarkerPrefix}{removed} chars]";
    }
}
