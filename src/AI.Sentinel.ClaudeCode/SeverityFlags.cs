namespace AI.Sentinel.ClaudeCode;

/// <summary>A set of finding severities.</summary>
[Flags]
internal enum SeverityFlags
{
    None = 0,
    Critical = 1,
    High = 2,
    Medium = 4,
    Low = 8,
}
