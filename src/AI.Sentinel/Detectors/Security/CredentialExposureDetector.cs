using System.Text.RegularExpressions;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using ZeroAlloc.Inject;
namespace AI.Sentinel.Detectors.Security;

[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed partial class CredentialExposureDetector : ILlmEscalatingDetector
{
    private static readonly DetectorId _id = new("SEC-02");
    private static readonly DetectionResult _clean = DetectionResult.Clean(_id);

    public DetectorId Id => _id;
    public DetectorCategory Category => DetectorCategory.Security;

    [GeneratedRegex(
        @"(password\s*[=:]\s*\S+|" +
        @"api[_-]?key\s*[=:]\s*\S+|" +
        @"secret[_-]?key\s*[=:]\s*\S+|" +
        @"Authorization\s*:\s*Bearer\s+\S+|" +
        @"AWS_SECRET_ACCESS_KEY\s*=\s*\S+|" +
        @"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----|" +
        @"ghp_[a-zA-Z0-9]{36}|" +
        @"sk-[a-zA-Z0-9]{32,})",
        RegexOptions.IgnoreCase | RegexOptions.ExplicitCapture | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex CredentialPattern();

    public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
    {
        var text = ctx.TextContent;
        var match = CredentialPattern().Match(text);
        if (!match.Success) return ValueTask.FromResult(_clean);
        return ValueTask.FromResult(DetectionResult.WithSeverity(_id, Severity.Critical,
            $"Credential exposure: '{match.Value[..Math.Min(20, match.Value.Length)]}...'"));
    }
}
