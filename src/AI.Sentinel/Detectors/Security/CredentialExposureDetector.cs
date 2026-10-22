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

    /// <summary>False: a secret is restored into the reply but never into a tool call's arguments.</summary>
    public bool RestoreIntoToolArguments => false;

    // Each pattern names a `value` group that covers only the secret, so a redacted span
    // keeps the key name. A quoted value takes the text between the quotes, may contain spaces
    // and backslash escapes, and runs to the end of the line when the closing quote is missing
    // (a truncated or streamed chunk), so nothing leaks. A double-quoted value whose closing quote
    // ends the value, followed by optional spaces or tabs and then a comma, a semicolon, a closing
    // parenthesis, a closing bracket or brace, a line break or the end of the text,
    // may span lines, as a JSON string holding a line break does in the scan text; otherwise only
    // its first line would be redacted. An unclosed quote never runs on to the next line's quote,
    // which is followed by more text, not by the end of a value. An unquoted value stops at whitespace,
    // skips leading ( [ { and excludes trailing . , ; " ' ) ] } so `abc`, `abc;` and `"abc"` all
    // yield the original `abc`. The unquoted form backtracks only over trailing punctuation, the
    // quoted forms use disjoint alternatives, and the multi-line form stops at the first unescaped
    // quote, so every form stays linear.
    // An unquoted value that is a bare JSON literal, null, true or false, ending where a value
    // ends, is no secret: {"password": null} names none. A secret that only starts like one,
    // such as `nullify123` or `false-positive-7`, still matches; a quoted "null" is a string.
    // Between the separator and the value: horizontal whitespace, plus one line break and
    // indentation only when the value is quoted, so YAML `password:\n  "abc"` is caught while
    // `password:\n  min_length: 8` is not.
    private const string Gap = @"[ \t]*(?:\r?\n[ \t]*(?=[""']))?";

    private const string Value =
        @"(?:""(?<value>(?:[^""\\]|\\[\s\S])+)""(?=[ \t]*(?:[,;)}\]\r\n]|$))|""(?<value>(?:[^""\\\r\n]|\\[^\r\n])+)""?|'(?<value>(?:[^'\\\r\n]|\\[^\r\n])+)'?|[(\[{]*(?!(?:null|true|false)(?:[\s.,;""')\]}]|$))(?<value>[^\s""'(\[{](?:\S*[^\s.,;""')\]}])?))";

    [GeneratedRegex(
        @"password[""']?\s*[=:]" + Gap + Value,
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex PasswordPattern();

    [GeneratedRegex(
        @"api[_-]?key[""']?\s*[=:]" + Gap + Value,
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex ApiKeyPattern();

    [GeneratedRegex(
        @"secret[_-]?key[""']?\s*[=:]" + Gap + Value,
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex SecretKeyPattern();

    [GeneratedRegex(
        @"Authorization[""']?\s*:\s*[""']?Bearer[ \t]+" + Value,
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex BearerPattern();

    [GeneratedRegex(
        @"AWS_SECRET_ACCESS_KEY[""']?\s*[=:]" + Gap + Value,
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex AwsSecretPattern();

    // From the BEGIN header through the matching END marker, or to the end of the text when
    // there is none. The second alternative consumes the rest of the input, so an input made
    // of many BEGIN headers without an END marker is scanned once rather than once per header.
    [GeneratedRegex(
        @"(?<value>-----BEGIN\s+(?:[A-Z]{2,12}\s+){0,2}PRIVATE\s+KEY-----(?:[\s\S]*?-----END\s+(?:[A-Z]{2,12}\s+){0,2}PRIVATE\s+KEY-----|[\s\S]*))",
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex PrivateKeyPattern();

    [GeneratedRegex(
        @"(?<value>ghp_[a-zA-Z0-9]{36})",
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex GithubTokenPattern();

    [GeneratedRegex(
        @"(?<value>sk-[a-zA-Z0-9]{32,})",
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex BareApiKeyPattern();

    public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
    {
        var text = ctx.TextContent;
        var placeholders = ctx.PlaceholdersExemptFor(_id);
        // The reason carries only the entity type; no part of the matched secret. A placeholder this call
        // minted is not a secret.
        if (RedactionSpanCollector.HasMatch(PasswordPattern(), text, placeholders)) return Hit("PASSWORD");
        if (RedactionSpanCollector.HasMatch(ApiKeyPattern(), text, placeholders)) return Hit("API_KEY");
        if (RedactionSpanCollector.HasMatch(SecretKeyPattern(), text, placeholders)) return Hit("SECRET_KEY");
        if (RedactionSpanCollector.HasMatch(BearerPattern(), text, placeholders)) return Hit("BEARER_TOKEN");
        if (RedactionSpanCollector.HasMatch(AwsSecretPattern(), text, placeholders)) return Hit("AWS_SECRET");
        if (RedactionSpanCollector.HasMatch(PrivateKeyPattern(), text, placeholders)) return Hit("PRIVATE_KEY");
        if (RedactionSpanCollector.HasMatch(GithubTokenPattern(), text, placeholders)) return Hit("GITHUB_TOKEN");
        if (RedactionSpanCollector.HasMatch(BareApiKeyPattern(), text, placeholders)) return Hit("API_KEY");
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
