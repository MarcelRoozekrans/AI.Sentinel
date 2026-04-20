using System.Text.RegularExpressions;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;

using ZeroAlloc.Inject;
namespace AI.Sentinel.Detectors.Security;

[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed partial class PiiLeakageDetector : ILlmEscalatingDetector
{
    private static readonly DetectorId _id = new("SEC-23");
    private static readonly DetectionResult _clean = DetectionResult.Clean(_id);

    public DetectorId Id => _id;
    public DetectorCategory Category => DetectorCategory.Security;

    [GeneratedRegex(
        @"(\d{3}-\d{2}-\d{4}|" +
        @"\b\d{3}[-.]\d{3}[-.]\d{4}\b|" +
        @"[A-Z]{2}\d{6}[A-D]|" +
        @"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b)",
        RegexOptions.ExplicitCapture | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex PiiPattern();

    public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
    {
        var text = ctx.TextContent;
        var match = PiiPattern().Match(text);
        return ValueTask.FromResult(match.Success
            ? DetectionResult.WithSeverity(_id, Severity.High,
                $"PII detected: '{match.Value[..Math.Min(8, match.Value.Length)]}...'")
            : _clean);
    }
}
