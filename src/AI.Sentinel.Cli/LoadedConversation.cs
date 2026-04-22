namespace AI.Sentinel.Cli;

public sealed record LoadedConversation(
    ConversationFormat Format,
    IReadOnlyList<ConversationTurn> Turns);
