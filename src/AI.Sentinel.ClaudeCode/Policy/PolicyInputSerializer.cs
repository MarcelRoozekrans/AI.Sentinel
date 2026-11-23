using System.Text.Json;

namespace AI.Sentinel.ClaudeCode.Policy;

/// <summary>Serializes <see cref="PolicyInput"/> to the JSON a policy reads.</summary>
internal static class PolicyInputSerializer
{
    public static string Serialize(PolicyInput input)
    {
        ArgumentNullException.ThrowIfNull(input);
        return JsonSerializer.Serialize(input, PolicyInputJsonContext.Default.PolicyInput);
    }
}
