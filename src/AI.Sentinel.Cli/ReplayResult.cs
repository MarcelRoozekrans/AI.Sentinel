using AI.Sentinel.Detection;

namespace AI.Sentinel.Cli;

public sealed record ReplayResult(
    string SchemaVersion,
    string File,
    ConversationFormat Format,
    int TurnCount,
    IReadOnlyList<TurnResult> Turns,
    Severity MaxSeverity);
