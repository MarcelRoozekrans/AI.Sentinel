using System.Text.RegularExpressions;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
namespace AI.Sentinel.Detectors.Security;

public sealed partial class PrivilegeEscalationDetector : IDetector
{
    private static readonly DetectorId _id = new("SEC-06");
    private static readonly DetectionResult _clean = DetectionResult.Clean(_id);

    public DetectorId Id => _id;
    public DetectorCategory Category => DetectorCategory.Security;

    [GeneratedRegex(
        @"(grant\s+(?:me\s+)?(?:admin|root|superuser|elevated)\s+(?:access|privileges?)|" +
        @"sudo\s+|run\s+as\s+(?:administrator|root)|escalate\s+(?:my\s+)?privileges?)",
        RegexOptions.IgnoreCase | RegexOptions.ExplicitCapture | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex EscalationPattern();

    public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
    {
        var text = ctx.TextContent;
        var match = EscalationPattern().Match(text);
        return ValueTask.FromResult(match.Success
            ? DetectionResult.WithSeverity(_id, Severity.High, $"Privilege escalation: '{match.Value}'")
            : _clean);
    }
}
