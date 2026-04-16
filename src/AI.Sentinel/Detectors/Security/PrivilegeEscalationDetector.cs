using System.Text.RegularExpressions;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
namespace AI.Sentinel.Detectors.Security;

public sealed partial class PrivilegeEscalationDetector : IDetector
{
    public DetectorId Id => new("SEC-16");
    public DetectorCategory Category => DetectorCategory.Security;

    [GeneratedRegex(
        @"(grant\s+(?:me\s+)?(?:admin|root|superuser|elevated)\s+(?:access|privileges?)|" +
        @"sudo\s+|run\s+as\s+(?:administrator|root)|escalate\s+(?:my\s+)?privileges?)",
        RegexOptions.IgnoreCase | RegexOptions.ExplicitCapture | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex EscalationPattern();

    public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
    {
        var text = string.Join(" ", ctx.Messages.Select(m => m.Text ?? ""));
        var match = EscalationPattern().Match(text);
        return ValueTask.FromResult(match.Success
            ? DetectionResult.WithSeverity(Id, Severity.High, $"Privilege escalation: '{match.Value}'")
            : DetectionResult.Clean(Id));
    }
}
