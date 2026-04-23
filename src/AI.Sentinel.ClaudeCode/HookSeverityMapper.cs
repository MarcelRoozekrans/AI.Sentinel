using AI.Sentinel.Detection;

namespace AI.Sentinel.ClaudeCode;

public static class HookSeverityMapper
{
    public static HookDecision Map(Severity severity, HookConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);
        return severity switch
        {
            Severity.Critical => config.OnCritical,
            Severity.High => config.OnHigh,
            Severity.Medium => config.OnMedium,
            Severity.Low => config.OnLow,
            _ => HookDecision.Allow,
        };
    }
}
