namespace AI.Sentinel.Detection;

/// <summary>A span of text a detector matched, located by offset so it can be replaced.</summary>
/// <param name="Start">Zero-based start offset in the scanned text.</param>
/// <param name="Length">Length of the match.</param>
/// <param name="EntityType">Entity label used for the placeholder, for example EMAIL.</param>
public readonly record struct RedactionSpan(int Start, int Length, string EntityType);
