using AI.Sentinel.Approvals;

namespace AI.Sentinel.Authorization;

internal sealed record ToolCallPolicyBinding(
    string Pattern,
    string PolicyName,
    ApprovalSpec? ApprovalSpec = null)
{
    public bool Matches(string toolName) => Matches(Pattern, toolName);

    /// <summary>Whether <paramref name="toolName"/> matches <paramref name="pattern"/>: ordinally, exactly, or by prefix
    /// when the pattern ends in <c>*</c>.</summary>
    public static bool Matches(string pattern, string toolName)
    {
        if (pattern.EndsWith('*'))
            return toolName.StartsWith(pattern[..^1], StringComparison.Ordinal);
        return string.Equals(pattern, toolName, StringComparison.Ordinal);
    }
}
