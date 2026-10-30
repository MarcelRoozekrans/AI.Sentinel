namespace AI.Sentinel.Detection;

/// <summary>What a semantic detector's scoring produced: its result and, next to it, its review candidate.</summary>
/// <param name="Result">The uncapped result, as <see cref="SemanticDetectorBase.AnalyzeAsync(SentinelContext, CancellationToken)"/>
/// returns it.</param>
/// <param name="Candidate">The text to review, or <see langword="null"/> when no text reached a bucket nor the
/// review threshold, and for a fast-path result.</param>
/// <param name="FromFastPath">Whether <paramref name="Result"/> is a rule-layer match, which is never capped nor reviewed.</param>
internal readonly record struct SemanticOutcome(DetectionResult Result, ReviewCandidate? Candidate, bool FromFastPath);
