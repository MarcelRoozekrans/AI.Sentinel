using Microsoft.Extensions.AI;

namespace AI.Sentinel.Cli;

public sealed record ConversationTurn(
    IReadOnlyList<ChatMessage> Prompt,
    ChatMessage Response);
