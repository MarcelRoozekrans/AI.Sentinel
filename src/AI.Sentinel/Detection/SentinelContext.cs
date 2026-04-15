using AI.Sentinel.Domain;
using Microsoft.Extensions.AI;

namespace AI.Sentinel.Detection;

public sealed record SentinelContext(
    AgentId SenderId,
    AgentId ReceiverId,
    SessionId SessionId,
    IReadOnlyList<ChatMessage> Messages,
    IReadOnlyList<AuditEntry> History,
    string? LlmId = null);
