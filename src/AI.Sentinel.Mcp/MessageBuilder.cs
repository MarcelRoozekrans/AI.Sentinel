using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using AI.Sentinel.Redaction;
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

    /// <summary>
    /// Collects the content of a tool result that the proxy can redact: what
    /// <see cref="CollectRedactable(IList{ContentBlock}, int, HashSet{string})"/> collects from its blocks, then
    /// <see cref="CallToolResult.StructuredContent"/> as JSON, whose <c>Apply</c> writes the redacted JSON back into
    /// <paramref name="result"/>. The structured content draws on the same <paramref name="maxScanBytes"/> budget,
    /// after the blocks.
    /// </summary>
    public static (List<HostContent> Content, List<Action<HostContent>> Apply, List<ChatMessage> Oversize) CollectRedactable(
        CallToolResult result, int maxScanBytes, HashSet<string> allowedMimes)
    {
        ArgumentNullException.ThrowIfNull(result);
        ArgumentNullException.ThrowIfNull(allowedMimes);

        var collector = new RedactableCollector(maxScanBytes);
        collector.AddBlocks(result.Content, allowedMimes);
        if (result.StructuredContent is { ValueKind: not (JsonValueKind.Undefined or JsonValueKind.Null) } json)
        {
            collector.Add(json.GetRawText(), HostContent.FromJson(json), redacted => result.StructuredContent = redacted.Json!.Value);
        }
        return collector.ToTuple();
    }

    /// <summary>
    /// Collects the content blocks the proxy can redact: the text of each <see cref="TextContentBlock"/>, and the
    /// text of each <see cref="EmbeddedResourceBlock"/> holding a <see cref="TextResourceContents"/> whose MIME type
    /// is in <paramref name="allowedMimes"/>.
    /// </summary>
    /// <param name="blocks">The content blocks, changed in place by <c>Apply</c>.</param>
    /// <param name="maxScanBytes">The total UTF-8 budget of the scan, as in 3.0. Items are taken in order while they
    /// fit in what is left. The first item that does not fit goes to <c>Oversize</c>, truncated to what is left, and
    /// is not redacted; items after it are neither redacted nor scanned, as the 3.0 truncation dropped them.</param>
    /// <param name="allowedMimes">The MIME allowlist of <see cref="ResourceReadInterceptor.ParseMimeAllowlist"/>.</param>
    /// <returns><c>Apply[i]</c> writes the redacted <c>Content[i]</c> back. Images, audio, blobs, resource links,
    /// non-allowlisted and empty items are left out and stay as they are.</returns>
    public static (List<HostContent> Content, List<Action<HostContent>> Apply, List<ChatMessage> Oversize) CollectRedactable(
        IList<ContentBlock>? blocks, int maxScanBytes, HashSet<string> allowedMimes)
    {
        ArgumentNullException.ThrowIfNull(allowedMimes);

        var collector = new RedactableCollector(maxScanBytes);
        collector.AddBlocks(blocks, allowedMimes);
        return collector.ToTuple();
    }

    /// <summary>Collects redactable items against one running byte budget.</summary>
    private sealed class RedactableCollector(int maxScanBytes)
    {
        private readonly List<HostContent> _content = [];
        private readonly List<Action<HostContent>> _apply = [];
        private readonly List<ChatMessage> _oversize = [];
        private int _remaining = Math.Max(maxScanBytes, 0);

        public void AddBlocks(IList<ContentBlock>? blocks, HashSet<string> allowedMimes)
        {
            if (blocks is null) return;

            foreach (var block in blocks)
            {
                switch (block)
                {
                    case TextContentBlock text when !string.IsNullOrEmpty(text.Text):
                        Add(text.Text, HostContent.FromText(text.Text), redacted => text.Text = redacted.Text!);
                        break;
                    case EmbeddedResourceBlock { Resource: TextResourceContents resource }
                        when !string.IsNullOrEmpty(resource.Text) && ResourceReadInterceptor.IsAllowedMime(resource.MimeType, allowedMimes):
                        Add(resource.Text, HostContent.FromText(resource.Text), redacted => resource.Text = redacted.Text!);
                        break;
                }
            }
        }

        /// <summary>Takes <paramref name="item"/> when <paramref name="text"/> fits in what is left of the budget.
        /// Otherwise the text is truncated to what is left and scanned unredacted, or dropped when nothing is left,
        /// and the budget is spent.</summary>
        public void Add(string text, HostContent item, Action<HostContent> write)
        {
            var bytes = Encoding.UTF8.GetByteCount(text);
            if (bytes <= _remaining)
            {
                _content.Add(item);
                _apply.Add(write);
                _remaining -= bytes;
                return;
            }

            if (_remaining > 0)
            {
                _oversize.Add(new ChatMessage(ChatRole.Assistant, TruncateIfNeeded(text, _remaining)));
            }
            _remaining = 0;
        }

        public (List<HostContent> Content, List<Action<HostContent>> Apply, List<ChatMessage> Oversize) ToTuple()
            => (_content, _apply, _oversize);
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
