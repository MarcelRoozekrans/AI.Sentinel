using AI.Sentinel.Audit;
using AI.Sentinel.Domain;
using Microsoft.Extensions.AI;

namespace AI.Sentinel.Detection;

public sealed class SentinelContext(
    AgentId SenderId,
    AgentId ReceiverId,
    SessionId SessionId,
    IReadOnlyList<ChatMessage> Messages,
    IReadOnlyList<AuditEntry> History,
    string? LlmId = null,
    string? systemPrompt = null)
{
    public AgentId SenderId { get; } = SenderId;
    public AgentId ReceiverId { get; } = ReceiverId;
    public SessionId SessionId { get; } = SessionId;
    public IReadOnlyList<ChatMessage> Messages { get; } = Messages;
    public IReadOnlyList<AuditEntry> History { get; } = History;
    public string? LlmId { get; } = LlmId;

    /// <summary>The conversation's system prompt, when one was supplied.</summary>
    /// <remarks>
    /// Carried on both scan legs so a detector can compare the model's output against it. The
    /// response leg scans only the generated message, so without this the prompt is unavailable
    /// exactly where a leak would appear.
    /// </remarks>
    public string? SystemPrompt { get; } = systemPrompt;

    private static readonly IReadOnlySet<string> NoPlaceholders = new HashSet<string>(StringComparer.Ordinal);

    /// <summary>
    /// The redaction placeholders, such as <c>[API_KEY_1]</c>, that the current call minted when it redacted
    /// the request. A redacting detector does not flag them as a value: they are what a redacted request
    /// looks like. Empty by default, so a surface that never redacts exempts nothing, and text that merely
    /// looks like a placeholder is judged like any other text.
    /// </summary>
    public IReadOnlySet<string> RedactionPlaceholders { get; init; } = NoPlaceholders;

    private string? _textContent;

    /// <summary>
    /// The concatenated text of all messages (non-text content parts are omitted), joined by a single space.
    /// Computed once and cached per context — detectors that join with a space separator should use this instead of string.Join.
    /// </summary>
    public string TextContent =>
        _textContent ??= string.Join(" ", Messages.Select(m => m.Text ?? ""));
}
