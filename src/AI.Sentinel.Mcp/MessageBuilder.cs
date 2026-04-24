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

    public static ChatMessage[] BuildToolCallRequest(CallToolRequestParams req)
    {
        var argsJson = SerializeArguments(req.Arguments);
        var text = $"tool:{req.Name} input:{argsJson}";
        return [new ChatMessage(ChatRole.User, text)];
    }

    public static ChatMessage[] BuildToolCallResponse(
        CallToolRequestParams req, CallToolResult result, int maxScanBytes)
    {
        var argsJson = SerializeArguments(req.Arguments);
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

    private static string SerializeArguments(IDictionary<string, JsonElement>? args)
    {
        if (args is null || args.Count == 0) return "{}";
        return JsonSerializer.Serialize(args, McpJsonContext.Default.IDictionaryStringJsonElement);
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

    private static string TruncateIfNeeded(string text, int maxScanBytes)
    {
        if (text.Length <= maxScanBytes) return text;
        var truncated = text[..maxScanBytes];
        var removed = text.Length - maxScanBytes;
        return $"{truncated}{TruncationMarkerPrefix}{removed} chars]";
    }
}
