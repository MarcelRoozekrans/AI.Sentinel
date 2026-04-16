using System.Text.RegularExpressions;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
namespace AI.Sentinel.Detectors.Security;

public sealed partial class DataExfiltrationDetector : IDetector
{
    private static readonly DetectorId _id = new("SEC-04");
    private static readonly DetectionResult _clean = DetectionResult.Clean(_id);

    public DetectorId Id => _id;
    public DetectorCategory Category => DetectorCategory.Security;

    [GeneratedRegex(@"[A-Za-z0-9+/]{12,}={0,2}", RegexOptions.ExplicitCapture | RegexOptions.Compiled, matchTimeoutMilliseconds: 1000)]
    private static partial Regex Base64Pattern();

    [GeneratedRegex(@"\b[0-9a-fA-F]{16,}\b", RegexOptions.ExplicitCapture | RegexOptions.Compiled, matchTimeoutMilliseconds: 1000)]
    private static partial Regex HexPattern();

    private static double Entropy(string s)
    {
        if (s.Length == 0) return 0;
        var freq = s.GroupBy(c => c).Select(g => (double)g.Count() / s.Length);
        return -freq.Sum(p => p * Math.Log2(p));
    }

    public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
    {
        var text = ctx.TextContent;
        var b64 = Base64Pattern().Match(text);
        if (b64.Success && Entropy(b64.Value) > 3.5)
            return ValueTask.FromResult(DetectionResult.WithSeverity(_id, Severity.High,
                "High-entropy base64 content — possible data exfiltration"));
        var hex = HexPattern().Match(text);
        if (hex.Success)
            return ValueTask.FromResult(DetectionResult.WithSeverity(_id, Severity.Medium,
                "Long hex string — possible encoded data exfiltration"));
        return ValueTask.FromResult(_clean);
    }
}
