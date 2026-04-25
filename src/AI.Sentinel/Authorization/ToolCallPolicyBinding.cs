namespace AI.Sentinel.Authorization;

internal sealed record ToolCallPolicyBinding(string Pattern, string PolicyName)
{
    public bool Matches(string toolName)
    {
        if (Pattern.EndsWith('*'))
            return toolName.StartsWith(Pattern[..^1], StringComparison.Ordinal);
        return string.Equals(Pattern, toolName, StringComparison.Ordinal);
    }
}
