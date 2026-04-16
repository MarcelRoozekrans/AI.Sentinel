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
    string? LlmId = null)
{
    public AgentId SenderId { get; } = SenderId;
    public AgentId ReceiverId { get; } = ReceiverId;
    public SessionId SessionId { get; } = SessionId;
    public IReadOnlyList<ChatMessage> Messages { get; } = Messages;
    public IReadOnlyList<AuditEntry> History { get; } = History;
    public string? LlmId { get; } = LlmId;

    private string? _textContent;

    /// <summary>
    /// The concatenated text of all messages (non-text content parts are omitted), joined by a single space.
    /// Computed once and cached per context — detectors that join with a space separator should use this instead of string.Join.
    /// </summary>
    public string TextContent =>
        _textContent ??= string.Join(" ", Messages.Select(m => m.Text ?? ""));
}
