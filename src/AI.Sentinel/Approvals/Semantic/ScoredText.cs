namespace AI.Sentinel.Approvals.Semantic;

/// <summary>A piece of tool-call text to score, the path it came from, and whether it was cut to the size cap.</summary>
internal readonly record struct ScoredText(string Path, string Text, bool Truncated);
