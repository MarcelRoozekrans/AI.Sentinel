using System.Text.RegularExpressions;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using ZeroAlloc.Inject;
namespace AI.Sentinel.Detectors.Security;

[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed partial class CredentialExposureDetector : ILlmEscalatingDetector, IRedactingDetector
{
    private static readonly DetectorId _id = new("SEC-02");
    private static readonly DetectionResult _clean = DetectionResult.Clean(_id);

    public DetectorId Id => _id;
    public DetectorCategory Category => DetectorCategory.Security;

    // Each pattern names a `value` group that covers only the secret, so a redacted
    // span keeps the key name. Whitespace runs are bounded so a long run of spaces
    // after a keyword cannot be rescanned from every keyword occurrence.

    [GeneratedRegex(
        @"password\s{0,32}[=:]\s{0,32}(?<value>\S+)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex PasswordPattern();

    [GeneratedRegex(
        @"api[_-]?key\s{0,32}[=:]\s{0,32}(?<value>\S+)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex ApiKeyPattern();

    [GeneratedRegex(
        @"secret[_-]?key\s{0,32}[=:]\s{0,32}(?<value>\S+)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex SecretKeyPattern();

    [GeneratedRegex(
        @"Authorization\s{0,32}:\s{0,32}Bearer\s{1,32}(?<value>\S+)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex BearerPattern();

    [GeneratedRegex(
        @"AWS_SECRET_ACCESS_KEY\s{0,32}=\s{0,32}(?<value>\S+)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex AwsSecretPattern();

    // From the BEGIN header through the matching END marker, or to the end of the text when
    // there is none. The second alternative consumes the rest of the input, so an input made
    // of many BEGIN headers without an END marker is scanned once rather than once per header.
    [GeneratedRegex(
        @"(?<value>-----BEGIN\s{1,8}(?:[A-Z]{2,12}\s{1,8}){0,2}PRIVATE\s{1,8}KEY-----(?:[\s\S]*?-----END\s{1,8}(?:[A-Z]{2,12}\s{1,8}){0,2}PRIVATE\s{1,8}KEY-----|[\s\S]*))",
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex PrivateKeyPattern();

    [GeneratedRegex(
        @"(?<value>ghp_[a-zA-Z0-9]{36})",
        RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex GithubTokenPattern();

    [GeneratedRegex(
        @"(?<value>sk-[a-zA-Z0-9]{32,})",
        RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex BareApiKeyPattern();

    public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
    {
        var text = ctx.TextContent;
        // The reason carries only the entity type; no part of the matched secret.
        if (PasswordPattern().IsMatch(text)) return Hit("PASSWORD");
        if (ApiKeyPattern().IsMatch(text)) return Hit("API_KEY");
        if (SecretKeyPattern().IsMatch(text)) return Hit("SECRET_KEY");
        if (BearerPattern().IsMatch(text)) return Hit("BEARER_TOKEN");
        if (AwsSecretPattern().IsMatch(text)) return Hit("AWS_SECRET");
        if (PrivateKeyPattern().IsMatch(text)) return Hit("PRIVATE_KEY");
        if (GithubTokenPattern().IsMatch(text)) return Hit("GITHUB_TOKEN");
        if (BareApiKeyPattern().IsMatch(text)) return Hit("API_KEY");
        return ValueTask.FromResult(_clean);
    }

    /// <inheritdoc />
    public IReadOnlyList<RedactionSpan> FindSpans(string text)
    {
        var spans = new List<RedactionSpan>();
        RedactionSpanCollector.Collect(PasswordPattern(), "PASSWORD", text, spans);
        RedactionSpanCollector.Collect(ApiKeyPattern(), "API_KEY", text, spans);
        RedactionSpanCollector.Collect(SecretKeyPattern(), "SECRET_KEY", text, spans);
        RedactionSpanCollector.Collect(BearerPattern(), "BEARER_TOKEN", text, spans);
        RedactionSpanCollector.Collect(AwsSecretPattern(), "AWS_SECRET", text, spans);
        RedactionSpanCollector.Collect(PrivateKeyPattern(), "PRIVATE_KEY", text, spans);
        RedactionSpanCollector.Collect(GithubTokenPattern(), "GITHUB_TOKEN", text, spans);
        RedactionSpanCollector.Collect(BareApiKeyPattern(), "API_KEY", text, spans);
        return RedactionSpanCollector.Normalize(spans);
    }

    private static ValueTask<DetectionResult> Hit(string entityType)
        => ValueTask.FromResult(DetectionResult.WithSeverity(_id, Severity.Critical,
            $"Credential exposure: {entityType}"));
}
