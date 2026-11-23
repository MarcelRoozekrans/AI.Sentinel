namespace AI.Sentinel.ClaudeCode.Policy;

/// <summary>The details of the tool kind. Only the members that apply to the kind are set.</summary>
internal sealed record PolicyDetails
{
    public ShellDetails? Shell { get; init; }

    public McpDetails? Mcp { get; init; }

    public IReadOnlyList<PolicyPath>? Paths { get; init; }

    public string? Url { get; init; }
}
