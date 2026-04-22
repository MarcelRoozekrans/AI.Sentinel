namespace AI.Sentinel.Cli;

public sealed record DiffEntry(
    int TurnIndex,
    string DetectorId,
    DiffKind Kind,
    string Message);
