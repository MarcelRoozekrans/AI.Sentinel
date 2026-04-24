using System.Text.RegularExpressions;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using ZeroAlloc.Inject;

namespace AI.Sentinel.Detectors.Security;

[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed partial class ExcessiveAgencyDetector : ILlmEscalatingDetector
{
    private static readonly DetectorId _id    = new("SEC-21");
    private static readonly DetectionResult _clean = DetectionResult.Clean(_id);

    public DetectorId Id => _id;
    public DetectorCategory Category => DetectorCategory.Security;

    [GeneratedRegex(
        @"\b(i\s+have\s+(written|created|sent|executed|modified|ran|run|deployed|spawned|deleted|removed)|" +
        @"i\s+(deployed|spawned)|wrote\s+to|uploaded\s+to)\b",
        RegexOptions.IgnoreCase | RegexOptions.ExplicitCapture | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex AgencyPattern();

    [GeneratedRegex(
        @"\b(deleted|removed|deployed|spawned)\b",
        RegexOptions.IgnoreCase | RegexOptions.ExplicitCapture | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex DestructivePattern();

    public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
    {
        var text = ctx.TextContent;
        var match = AgencyPattern().Match(text);
        if (!match.Success) return ValueTask.FromResult(_clean);

        var severity = DestructivePattern().IsMatch(match.Value) ? Severity.High : Severity.Medium;
        return ValueTask.FromResult(DetectionResult.WithSeverity(_id, severity,
            $"Unsolicited autonomous action: '{match.Value}'"));
    }
}
