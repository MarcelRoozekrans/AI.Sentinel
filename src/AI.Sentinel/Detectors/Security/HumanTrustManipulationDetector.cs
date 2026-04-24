using System.Text.RegularExpressions;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using ZeroAlloc.Inject;

namespace AI.Sentinel.Detectors.Security;

[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed partial class HumanTrustManipulationDetector : ILlmEscalatingDetector
{
    private static readonly DetectorId _id    = new("SEC-22");
    private static readonly DetectionResult _clean = DetectionResult.Clean(_id);

    public DetectorId Id => _id;
    public DetectorCategory Category => DetectorCategory.Security;

    [GeneratedRegex(
        @"\b(you\s+can\s+trust\s+me|i\s+care\s+about\s+you|as\s+your\s+friend|" +
        @"i('m|\s+am)\s+on\s+your\s+side|only\s+i\s+understand)\b",
        RegexOptions.IgnoreCase | RegexOptions.ExplicitCapture | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex RapportPattern();

    [GeneratedRegex(
        @"\bi\s+am\s+your\s+(assistant|advisor|guardian|protector)\b",
        RegexOptions.IgnoreCase | RegexOptions.ExplicitCapture | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex AuthorityPattern();

    public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
    {
        var text = ctx.TextContent;

        var authority = AuthorityPattern().Match(text);
        if (authority.Success)
            return ValueTask.FromResult(DetectionResult.WithSeverity(_id, Severity.High,
                $"Authority impersonation: '{authority.Value}'"));

        var rapport = RapportPattern().Match(text);
        if (rapport.Success)
            return ValueTask.FromResult(DetectionResult.WithSeverity(_id, Severity.Medium,
                $"Trust manipulation: '{rapport.Value}'"));

        return ValueTask.FromResult(_clean);
    }
}
