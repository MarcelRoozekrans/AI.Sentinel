namespace AI.Sentinel.ClaudeCode;

/// <summary>Result a hook CLI writes to stdout. <see cref="Decision"/> is always present; every other member is optional.</summary>
public sealed record HookOutput
{
    public required HookDecision Decision { get; init; }
    public string? Reason { get; init; }
}
