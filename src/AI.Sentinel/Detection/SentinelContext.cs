using System.Text;
using System.Text.Json;
using AI.Sentinel.Audit;
using AI.Sentinel.Domain;
using Microsoft.Extensions.AI;

namespace AI.Sentinel.Detection;

public sealed class SentinelContext(
    AgentId SenderId,
    AgentId ReceiverId,
    SessionId SessionId,
    IReadOnlyList<ChatMessage> Messages,
    IReadOnlyList<AuditEntry> History)
{
    public AgentId SenderId { get; } = SenderId;
    public AgentId ReceiverId { get; } = ReceiverId;
    public SessionId SessionId { get; } = SessionId;
    public IReadOnlyList<ChatMessage> Messages { get; } = Messages;
    public IReadOnlyList<AuditEntry> History { get; } = History;

    /// <summary>The identifier of the model the call targets, when known.</summary>
    public string? LlmId { get; init; }

    /// <summary>The conversation's system prompt, when one was supplied.</summary>
    /// <remarks>
    /// Carried on both scan legs so a detector can compare the model's output against it. The
    /// response leg scans only the generated message, so without this the prompt is unavailable
    /// exactly where a leak would appear.
    /// </remarks>
    public string? SystemPrompt { get; init; }

    private static readonly IReadOnlySet<string> NoPlaceholders = new HashSet<string>(StringComparer.Ordinal);

    /// <summary>
    /// The redaction placeholders, such as <c>[API_KEY_1_k3f9x2]</c>, that the current call minted when it redacted
    /// the request, plus those minted by every enclosing Sentinel call in its parent chain, when this call runs
    /// below another one. A redacting detector does not flag them as a value: they are what a redacted request
    /// looks like. Empty by default, so a surface that never redacts exempts nothing, and text that merely
    /// looks like a placeholder is judged like any other text.
    /// </summary>
    public IReadOnlySet<string> RedactionPlaceholders { get; init; } = NoPlaceholders;

    /// <summary>
    /// Every placeholder-shaped token in the redacted request the model was sent, for the response scan.
    /// Only a detector listed in <see cref="RedactingDetectorIds"/> may treat them as exempt: that detector
    /// redacted the request, so a token still sitting where its value would be was minted or judged not a value.
    /// For any other detector, such a token may be a real secret that reached the model as it was.
    /// </summary>
    public IReadOnlySet<string> RequestPlaceholders { get; init; } = NoPlaceholders;

    /// <summary>Ids of the detectors that redacted the request of this call.</summary>
    public IReadOnlySet<string> RedactingDetectorIds { get; init; } = NoPlaceholders;

    private readonly int _newMessagesFrom;

    /// <summary>
    /// The index in <see cref="Messages"/> from which the messages are new in this scan. The messages before it are
    /// history, which a detector may read for context. 0, the default, means every message is new. Out-of-range
    /// values are clamped: below 0 to 0, and above the message count to the count, which means nothing is new.
    /// </summary>
    public int NewMessagesFrom
    {
        get => _newMessagesFrom;
        init => _newMessagesFrom = Math.Clamp(value, 0, Messages.Count);
    }

    /// <summary>
    /// The placeholders <paramref name="detector"/> must not flag as a value: <see cref="RedactionPlaceholders"/>,
    /// plus <see cref="RequestPlaceholders"/> when that detector redacted this call's request.
    /// </summary>
    public IReadOnlySet<string> PlaceholdersExemptFor(DetectorId detector)
    {
        ArgumentNullException.ThrowIfNull(detector);
        if (RequestPlaceholders.Count == 0 || !RedactingDetectorIds.Contains(detector.Value))
        {
            return RedactionPlaceholders;
        }

        var exempt = new HashSet<string>(RedactionPlaceholders, StringComparer.Ordinal);
        exempt.UnionWith(RequestPlaceholders);
        return exempt;
    }

    private string? _textContent;

    /// <summary>
    /// The detection text of all messages, joined by a single space. A message's detection text is its
    /// <see cref="ChatMessage.Text"/> followed by its tool calls and tool results, so an in-process tool loop is
    /// scanned like the hooks and the MCP proxy scan it. Other non-text content, such as images, is omitted.
    /// Computed once and cached per context — detectors that join with a space separator should use this instead of string.Join.
    /// </summary>
    public string TextContent =>
        _textContent ??= string.Join(" ", Messages.Select(MessageText));

    /// <summary>
    /// The text a detector judges for <paramref name="message"/>: its <see cref="ChatMessage.Text"/>, followed by each
    /// tool call and tool result it carries, in content order, separated by a single space.
    /// </summary>
    /// <remarks>
    /// <para>In an agent loop a tool call arrives as <see cref="FunctionCallContent"/> and its result as
    /// <see cref="FunctionResultContent"/>, both with an empty <see cref="ChatMessage.Text"/>, so without this the
    /// detectors would see neither.</para>
    /// <list type="bullet">
    /// <item><description>A <see cref="FunctionCallContent"/> or <see cref="McpServerToolCallContent"/> reads
    /// <c>tool:{name} input:{arguments}</c>, with the arguments as compact JSON: see <see cref="ToolCallText"/>.</description></item>
    /// <item><description>A <see cref="FunctionResultContent"/> reads as its result: a string as it is, a
    /// <see cref="JsonElement"/> as its raw text, anything else as compact JSON.</description></item>
    /// <item><description>A hosted tool call or result, of an MCP server, code interpreter, web search or image
    /// generation tool, reads as the text it carries: the queries of a web search call, and the text content of the
    /// inputs or outputs of the others.</description></item>
    /// </list>
    /// <para>A value that cannot be serialized is left out rather than failing the scan: the pipeline turns a
    /// detector exception into a Clean result for the whole scan, so letting it escape would hide every other
    /// message. A message with no tool content returns its <see cref="ChatMessage.Text"/> instance unchanged.</para>
    /// </remarks>
    internal static string MessageText(ChatMessage message)
    {
        ArgumentNullException.ThrowIfNull(message);

        var text = message.Text ?? string.Empty;
        StringBuilder? builder = null;
        foreach (var content in message.Contents)
        {
            if (content is TextContent) continue;

            var toolText = ToolText(content);
            if (string.IsNullOrEmpty(toolText)) continue;

            builder ??= new StringBuilder(text);
            if (builder.Length > 0) builder.Append(' ');
            builder.Append(toolText);
        }

        return builder?.ToString() ?? text;
    }

    /// <summary>The text of a tool call as every surface renders it for detection: <c>tool:{name} input:{arguments}</c>.</summary>
    /// <remarks>The Claude Code and Copilot hooks and the MCP proxy scan a tool call in this shape too, so a detector
    /// sees the same text whichever surface the call came through.</remarks>
    internal static string ToolCallText(string? name, string? arguments) => $"tool:{name} input:{arguments}";

    private static string? ToolText(AIContent content) => content switch
    {
        FunctionCallContent call => ToolCallText(call.Name, ArgumentsText(call.Arguments)),
        FunctionResultContent { Result: { } result } => ResultText(result),
        McpServerToolCallContent mcp => ToolCallText(mcp.Name, ArgumentsText(mcp.Arguments)),
        McpServerToolResultContent mcp => ContentsText(mcp.Outputs),
        CodeInterpreterToolCallContent code => ContentsText(code.Inputs),
        CodeInterpreterToolResultContent code => ContentsText(code.Outputs),
        WebSearchToolCallContent search => search.Queries is { Count: > 0 } queries ? string.Join(" ", queries) : null,
        WebSearchToolResultContent search => ContentsText(search.Outputs),
        ImageGenerationToolResultContent image => ContentsText(image.Outputs),
        _ => null,
    };

    /// <summary>The text content of the inputs or outputs of a hosted tool, with any tool content nested in them.</summary>
    private static string? ContentsText(IList<AIContent>? contents)
    {
        if (contents is null || contents.Count == 0) return null;

        StringBuilder? builder = null;
        foreach (var content in contents)
        {
            var text = content is TextContent t ? t.Text : ToolText(content);
            if (string.IsNullOrEmpty(text)) continue;

            builder ??= new StringBuilder();
            if (builder.Length > 0) builder.Append(' ');
            builder.Append(text);
        }

        return builder?.ToString();
    }

    /// <summary><see cref="AIJsonUtilities.DefaultOptions"/> without indentation, so a value reads as compact JSON.</summary>
    private static readonly JsonSerializerOptions CompactJsonOptions = CreateCompactJsonOptions();

    private static JsonSerializerOptions CreateCompactJsonOptions()
    {
        var options = new JsonSerializerOptions(AIJsonUtilities.DefaultOptions) { WriteIndented = false };
        options.MakeReadOnly();
        return options;
    }

    private static string ArgumentsText(IDictionary<string, object?>? arguments) =>
        arguments is null ? string.Empty : Serialize(arguments, typeof(IDictionary<string, object?>));

    /// <summary>A string result as it is, a <see cref="JsonElement"/> as its raw text, anything else as compact JSON;
    /// an empty string for a result that cannot be serialized.</summary>
    /// <remarks>Results that <see cref="FunctionInvokingChatClient"/> produces are already a <see cref="JsonElement"/>.</remarks>
    private static string ResultText(object result) => result switch
    {
        string text => text,
        JsonElement { ValueKind: JsonValueKind.Undefined } => string.Empty,
        JsonElement element => element.GetRawText(),
        _ => Serialize(result, result.GetType()),
    };

    /// <summary>Compact JSON for <paramref name="value"/>, or an empty string when it cannot be serialized.</summary>
    /// <remarks>
    /// The options resolve through MEAI's source-generated contract and, where it is enabled, reflection. Under native
    /// AOT a type that no source-generated context covers throws <see cref="NotSupportedException"/>, and a cycle
    /// throws <see cref="JsonException"/> anywhere; either way the value is left out.
    /// </remarks>
    private static string Serialize(object value, Type type)
    {
        try
        {
            return JsonSerializer.Serialize(value, CompactJsonOptions.GetTypeInfo(type));
        }
        catch (Exception ex) when (ex is NotSupportedException or JsonException)
        {
            return string.Empty;
        }
    }
}
