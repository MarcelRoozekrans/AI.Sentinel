using System.Text.RegularExpressions;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
namespace AI.Sentinel.Detectors.Security;

public sealed partial class CredentialExposureDetector : ILlmEscalatingDetector
{
    public DetectorId Id => new("SEC-02");
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
        var text = string.Join(" ", ctx.Messages.Select(m => m.Text ?? ""));
        var match = CredentialPattern().Match(text);
        if (!match.Success) return ValueTask.FromResult(DetectionResult.Clean(Id));
        return ValueTask.FromResult(DetectionResult.WithSeverity(Id, Severity.Critical,
            $"Credential exposure: '{match.Value[..Math.Min(20, match.Value.Length)]}...'"));
    }
}
