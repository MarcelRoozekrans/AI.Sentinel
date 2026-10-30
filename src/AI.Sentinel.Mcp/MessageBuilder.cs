using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using AI.Sentinel.Detection;
using AI.Sentinel.Redaction;
using Microsoft.Extensions.AI;
using ModelContextProtocol.Protocol;

namespace AI.Sentinel.Mcp;

/// <summary>Maps MCP protocol models to <see cref="ChatMessage"/> arrays for Sentinel scanning.</summary>
/// <remarks>The text is passed whole. The pipeline is the one place that cuts it to
/// <see cref="SentinelOptions.MaxScanBytes"/>, which the proxy sets from <c>SENTINEL_MCP_MAX_SCAN_BYTES</c>, and it
/// reports content over the budget as <c>SEC-00</c> (#439).</remarks>
internal static class MessageBuilder
{
    private const string Separator = "\n---\n";

    /// <summary>Builds the request-side scan payload for a <c>tools/call</c> invocation.</summary>
    /// <param name="req">The incoming tool-call request.</param>
    public static ChatMessage[] BuildToolCallRequest(CallToolRequestParams req)
    {
        var argsJson = SerializeArguments(req.Arguments);
        var text = SentinelContext.ToolCallText(req.Name, argsJson);
        return [new ChatMessage(ChatRole.User, text)];
    }

    /// <summary>Builds the response-side scan payload (request context + result text).</summary>
    /// <param name="req">The original tool-call request (for argument context).</param>
    /// <param name="result">The tool-call result to scan.</param>
    public static ChatMessage[] BuildToolCallResponse(CallToolRequestParams req, CallToolResult result)
    {
        var argsJson = SerializeArguments(req.Arguments);
        var requestText = SentinelContext.ToolCallText(req.Name, argsJson);
        var responseText = ExtractScannableText(result.Content);

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
    /// the caller is responsible for filtering out non-text (blob) variants and applying the MIME allowlist before
    /// invoking this helper.
    /// </remarks>
    public static ChatMessage BuildResourceRead(string text)
        => new(ChatRole.Tool, text);

    /// <summary>Builds the scan payload for a <c>prompts/get</c> response.</summary>
    /// <param name="result">The prompt result to scan.</param>
    public static ChatMessage[] BuildPromptGetResponse(GetPromptResult result)
    {
        var flattened = FlattenPromptMessages(result.Messages);
        if (string.IsNullOrEmpty(flattened))
        {
            return [];
        }
        return [new ChatMessage(ChatRole.Assistant, flattened)];
    }

    /// <summary>
    /// Collects the content of a tool result that the proxy can redact: what
    /// <see cref="CollectRedactable(IList{ContentBlock}, HashSet{string})"/> collects from its blocks, then
    /// <see cref="CallToolResult.StructuredContent"/> as JSON, whose <c>Apply</c> writes the redacted JSON back into
    /// <paramref name="result"/>.
    /// </summary>
    public static (List<HostContent> Content, List<Action<HostContent>> Apply) CollectRedactable(
        CallToolResult result, HashSet<string> allowedMimes)
    {
        ArgumentNullException.ThrowIfNull(result);
        ArgumentNullException.ThrowIfNull(allowedMimes);

        var collector = new RedactableCollector();
        collector.AddBlocks(result.Content, allowedMimes);
        if (result.StructuredContent is { ValueKind: not (JsonValueKind.Undefined or JsonValueKind.Null) } json)
        {
            collector.Add(HostContent.FromJson(json), redacted => result.StructuredContent = redacted.Json!.Value);
        }
        return collector.ToTuple();
    }

    /// <summary>
    /// Collects the content blocks the proxy can redact: the text of each <see cref="TextContentBlock"/>, and the
    /// text of each <see cref="EmbeddedResourceBlock"/> holding a <see cref="TextResourceContents"/> whose MIME type
    /// is in <paramref name="allowedMimes"/>.
    /// </summary>
    /// <param name="blocks">The content blocks, changed in place by <c>Apply</c>.</param>
    /// <param name="allowedMimes">The MIME allowlist of <see cref="ResourceReadInterceptor.ParseMimeAllowlist"/>.</param>
    /// <returns><c>Apply[i]</c> writes the redacted <c>Content[i]</c> back. Every item is collected whatever its size:
    /// redaction runs on the whole item, and the scan reports content over <see cref="SentinelOptions.MaxScanBytes"/>
    /// as <c>SEC-00</c>. Images, audio, blobs, resource links, non-allowlisted and empty items are left out and stay as
    /// they are.</returns>
    public static (List<HostContent> Content, List<Action<HostContent>> Apply) CollectRedactable(
        IList<ContentBlock>? blocks, HashSet<string> allowedMimes)
    {
        ArgumentNullException.ThrowIfNull(allowedMimes);

        var collector = new RedactableCollector();
        collector.AddBlocks(blocks, allowedMimes);
        return collector.ToTuple();
    }

    /// <summary>Collects redactable items with the write-back of each.</summary>
    private sealed class RedactableCollector
    {
        private readonly List<HostContent> _content = [];
        private readonly List<Action<HostContent>> _apply = [];

        public void AddBlocks(IList<ContentBlock>? blocks, HashSet<string> allowedMimes)
        {
            if (blocks is null) return;

            foreach (var block in blocks)
            {
                switch (block)
                {
                    case TextContentBlock text when !string.IsNullOrEmpty(text.Text):
                        Add(HostContent.FromText(text.Text), redacted => text.Text = redacted.Text!);
                        break;
                    case EmbeddedResourceBlock { Resource: TextResourceContents resource }
                        when !string.IsNullOrEmpty(resource.Text) && ResourceReadInterceptor.IsAllowedMime(resource.MimeType, allowedMimes):
                        Add(HostContent.FromText(resource.Text), redacted => resource.Text = redacted.Text!);
                        break;
                }
            }
        }

        public void Add(HostContent item, Action<HostContent> write)
        {
            _content.Add(item);
            _apply.Add(write);
        }

        public (List<HostContent> Content, List<Action<HostContent>> Apply) ToTuple() => (_content, _apply);
    }

    private static string SerializeArguments(IDictionary<string, JsonElement>? args)
    {
        if (args is null || args.Count == 0) return "{}";
        return JsonSerializer.Serialize(args, McpJsonContext.Default.IDictionaryStringJsonElement);
    }

    private static string ExtractScannableText(IList<ContentBlock>? blocks)
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

        return sb.ToString();
    }

    private static string FlattenPromptMessages(IList<PromptMessage>? messages)
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

        return sb.ToString();
    }
}
