namespace AI.Sentinel.ClaudeCode.Policy;

/// <summary>A path a file kind touches.</summary>
/// <param name="Path">The path as the tool was given it, made absolute when it can be resolved.</param>
/// <param name="InRepository">True when the resolved path lies inside the repository root. False when the root is unknown.</param>
internal sealed record PolicyPath(string Path, bool InRepository);
