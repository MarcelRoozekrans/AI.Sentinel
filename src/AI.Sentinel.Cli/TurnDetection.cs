using AI.Sentinel.Detection;

namespace AI.Sentinel.Cli;

public sealed record TurnDetection(
    string DetectorId,
    Severity Severity,
    string Reason);
