namespace AI.Sentinel.ClaudeCode.Resident;

/// <summary>The content of <see cref="ResidentState.PinnedKeysFile"/>.</summary>
internal sealed record PinnedKeysFileContent
{
    public string? Organisation { get; init; }

    public List<string>? Keys { get; init; }
}
