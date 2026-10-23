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
    // which is followed by more text, not by the end of a value. An unquoted value stops at whitespace
    // or at a quote, escaped or not, that closes a string, so `ab"cd` stays whole while in
    // `["KEY=abc","B=x"]` the next string is not taken in. It never ends on the backslash of an
    // escaped quote, because covering the backslash would cover the quote it escapes. It
    // skips leading ( [ { and excludes trailing . , ; " ' ) ] } so `abc`, `abc;` and `"abc"` all
    // yield the original `abc`. The unquoted form backtracks only over trailing punctuation, the
    // quoted forms use disjoint alternatives, and the multi-line form stops at the first unescaped
    // quote, so every form stays linear.
    // An unquoted value that is a bare JSON literal, null, true or false, ending where a value
    // ends, is no secret: {"password": null} names none. A secret that only starts like one,
    // such as `nullify123` or `false-positive-7`, still matches; a quoted "null" is a string.
    // An unquoted value that starts with = is a comparison, as in secret == "abc"; inside quotes it is a secret.
    // Between the separator and the value: horizontal whitespace, plus one line break and
    // indentation only when the value is quoted, so YAML `password:\n  "abc"` is caught while
    // `password:\n  min_length: 8` is not.
    // A JSON document inside a JSON string, such as a tool's text block, reads \"password\": \"abc\" in the
    // scan text: KeyEnd lets a backslash precede the key's closing quote, and the first two Value forms take
    // the text between escaped quotes, at that escape level, so an escaped quote inside the value (\\\") stays
    // in it; an unclosed one runs to the end of the line, as the plain quoted form does.
    private const string KeyEnd = @"(?:\\?[""'])?\s*[=:]";

    private const string Gap = @"[ \t]*(?:\r?\n[ \t]*(?=[""']))?";

    // One character of a value between escaped quotes, at the escape level of the text around it.
    private const string EscapedChar = @"(?:[^""\\]|\\[^""\\]|\\\\(?:[^""\\]|\\\\|\\""|\\[^""\\]))";
    private const string EscapedLineChar = @"(?:[^""\\\r\n]|\\[^""\\\r\n]|\\\\(?:[^""\\\r\n]|\\\\|\\""|\\[^""\\\r\n]))";

    // What stands where a secret would but is none: a whole reference such as ${VAR}, ${{ secrets.X }} or
    // $(cmd), a whole <placeholder>, an environment lookup such as process.env.X, os.environ, getenv(, ENV[ or
    // Environment.GetEnvironmentVariable(, or your_… template text. A value that only starts like ${, $( or <
    // is still a secret. Each shape is bounded, so an unclosed ${{ or $( after many keys costs a constant per key
    // rather than a scan to the end of the line.
    private const string NotReference =
        @"(?!(?:\$\{\{[^}\r\n]{0,256}\}\}|\$\{[^}\s""']{0,256}\}|\$\([^)\r\n]{0,256}\)|<[\w .-]{1,64}>)(?:[""'\s,;)\]}]|\\[""']|$)" +
        @"|process\.env\b|os\.environ\b|(?:os\.|System\.)?getenv\(|ENV\[|Environment\.GetEnvironmentVariable\(|your[_-])";

    // A type annotation, as in access_token: str or accessToken: string;.
    private const string NotTypeName = @"(?!(?:string|str|int|bool|bytes)(?:[\s.,;:=)\]}>|]|$)|Optional\[)";

    // A quote, escaped or not, that closes a string: followed by a separator, a closing bracket or the end.
    private const string ClosingQuote = @"""(?:[\s,;:)\]}]|$)";

    private const string Value =
        @"(?:\\""" + NotReference + @"(?<value>" + EscapedChar + @"+)\\""" +
        @"|\\""" + NotReference + @"(?<value>" + EscapedLineChar + @"+)(?=\r?\n|$)" +
        @"|""" + NotReference + @"(?<value>(?:[^""\\]|\\[\s\S])+)""(?=[ \t]*(?:[,;)}\]\r\n]|$))" +
        @"|""" + NotReference + @"(?<value>(?:[^""\\\r\n]|\\[^\r\n])+)""?" +
        @"|'" + NotReference + @"(?<value>(?:[^'\\\r\n]|\\[^\r\n])+)'?" +
        @"|[(\[{]*(?!(?:null|true|false)(?:[\s.,;""')\]}]|$))(?!\\[""'])(?!=)" + NotReference + NotTypeName +
        @"(?<value>[^\s""'(\[{](?:(?:[^\s""\\]|\\(?!" + ClosingQuote + @")|""(?!(?:[\s,;:)\]}]|$)))*[^\s.,;""')\]}\\])?))";

    [GeneratedRegex(
        @"password" + KeyEnd + Gap + Value,
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex PasswordPattern();

    [GeneratedRegex(
        @"api[_-]?key" + KeyEnd + Gap + Value,
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex ApiKeyPattern();

    [GeneratedRegex(
        @"secret[_-]?key" + KeyEnd + Gap + Value,
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex SecretKeyPattern();

    [GeneratedRegex(
        @"Authorization(?:\\?[""'])?\s*:\s*(?:\\?[""'])?Bearer[ \t]+" + Value,
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex BearerPattern();

    [GeneratedRegex(
        @"AWS_SECRET_ACCESS_KEY" + KeyEnd + Gap + Value,
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex AwsSecretPattern();

    // A key whose last word is secret, such as client_secret, WEBHOOK_SECRET, ClientSecret or secret itself. secret_key and
    // AWS_SECRET_ACCESS_KEY keep their own patterns; secrets and SECRET_NAME do not end in the word.
    [GeneratedRegex(
        @"(?:(?<![A-Za-z0-9])secret|(?-i:(?<=[a-z0-9])Secret))" + KeyEnd + Gap + Value,
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex SecretPattern();

    // A token key that names a credential: access_token, refresh_token, id_token, Session-Token and the like.
    // A bare token, next_page_token or max_tokens names none, so only these prefixes count. id-token with a
    // hyphen is a GitHub Actions permission, not a credential; idToken and IdToken are.
    [GeneratedRegex(
        @"(?<![A-Za-z0-9])(?:id_|(?-i:[Ii]d(?=Token))|(?:access|refresh|auth|bearer|api|session|private|personal[_-]?access)[_-]?)token" + KeyEnd + Gap + Value,
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex CredentialTokenPattern();

    // An environment-style name in capitals ending in _TOKEN, such as API_TOKEN or GITHUB_TOKEN. Case-sensitive,
    // so a lower-case pagination key does not match.
    [GeneratedRegex(
        @"(?<=[A-Z0-9]_)TOKEN" + KeyEnd + Gap + Value,
        RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex EnvTokenPattern();

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
        if (RedactionSpanCollector.HasMatch(SecretPattern(), text, placeholders)) return Hit("SECRET");
        if (RedactionSpanCollector.HasMatch(CredentialTokenPattern(), text, placeholders)) return Hit("TOKEN");
        if (RedactionSpanCollector.HasMatch(EnvTokenPattern(), text, placeholders)) return Hit("TOKEN");
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
        RedactionSpanCollector.Collect(SecretPattern(), "SECRET", text, spans);
        RedactionSpanCollector.Collect(CredentialTokenPattern(), "TOKEN", text, spans);
        RedactionSpanCollector.Collect(EnvTokenPattern(), "TOKEN", text, spans);
        RedactionSpanCollector.Collect(PrivateKeyPattern(), "PRIVATE_KEY", text, spans);
        RedactionSpanCollector.Collect(GithubTokenPattern(), "GITHUB_TOKEN", text, spans);
        RedactionSpanCollector.Collect(BareApiKeyPattern(), "API_KEY", text, spans);
        return RedactionSpanCollector.Normalize(spans);
    }

    private static ValueTask<DetectionResult> Hit(string entityType)
        => ValueTask.FromResult(DetectionResult.WithSeverity(_id, Severity.Critical,
            $"Credential exposure: {entityType}"));
}
