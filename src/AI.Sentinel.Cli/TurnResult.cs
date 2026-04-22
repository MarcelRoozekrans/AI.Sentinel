using AI.Sentinel.Detection;

namespace AI.Sentinel.Cli;

public sealed record TurnResult(
    int Index,
    Severity MaxSeverity,
    IReadOnlyList<TurnDetection> Detections);
