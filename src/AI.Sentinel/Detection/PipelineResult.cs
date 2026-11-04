using AI.Sentinel.Domain;

namespace AI.Sentinel.Detection;

public sealed record PipelineResult(
    ThreatRiskScore Score,
    IReadOnlyList<DetectionResult> Detections)
{
    public bool IsClean => Score.Value == 0;
    public Severity MaxSeverity => Detections.Count == 0
        ? Severity.None
        : Detections.Max(d => d.Severity);

    /// <summary>The detectors that did not run to completion in this scan, one entry each, in the order the
    /// pipeline holds them. Empty for a complete scan. A failed detector is otherwise invisible here: it is Clean,
    /// so <see cref="IsClean"/> alone cannot tell "nothing found" from "could not look".</summary>
    /// <remarks>An <see langword="init"/> property rather than a constructor parameter, so the public constructor
    /// and <c>Deconstruct</c> stay as they were.</remarks>
    public IReadOnlyList<DetectorFailure> Failures { get; init; } = [];

    /// <summary>Whether every detector ran to completion, so a clean result means nothing was found rather than
    /// that something could not be checked.</summary>
    public bool IsComplete => Failures.Count == 0;
}
