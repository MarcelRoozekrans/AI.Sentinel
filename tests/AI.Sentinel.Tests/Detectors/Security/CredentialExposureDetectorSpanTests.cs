using Xunit;
using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using AI.Sentinel.Detectors.Security;
using AI.Sentinel.Domain;
using Microsoft.Extensions.AI;

namespace AI.Sentinel.Tests.Detectors.Security;

public class CredentialExposureDetectorSpanTests
{
    private const string GhToken = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";
    private const string SkToken = "sk-abcdefghijklmnopqrstuvwxyz012345";
    private const string Pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----";

    private static SentinelContext Ctx(string text) => new(
        new AgentId("a"), new AgentId("b"), SessionId.New(),
        new List<ChatMessage> { new(ChatRole.User, text) }, new List<AuditEntry>());

    [Fact]
    public void FindSpans_ApiKeyAssignment_CoversValueOnly()
    {
        var span = Assert.Single(new CredentialExposureDetector().FindSpans("api_key=abc123def"));
        Assert.Equal(new RedactionSpan(8, 9, "API_KEY"), span);
    }

    [Theory]
    [InlineData("password: hunter2", "hunter2", "PASSWORD")]
    [InlineData("secret_key = s3cr3t", "s3cr3t", "SECRET_KEY")]
    [InlineData("AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI", "wJalrXUtnFEMI", "AWS_SECRET")]
    public void FindSpans_KeywordAssignments_CoverValueOnly(string text, string value, string entity)
    {
        var span = Assert.Single(new CredentialExposureDetector().FindSpans(text));
        Assert.Equal(new RedactionSpan(text.IndexOf(value, StringComparison.Ordinal), value.Length, entity), span);
    }

    [Fact]
    public void FindSpans_BearerHeader_CoversToken()
    {
        const string text = "Authorization: Bearer eyJhbGciOi.abc.def";
        var span = Assert.Single(new CredentialExposureDetector().FindSpans(text));
        Assert.Equal(new RedactionSpan(text.IndexOf("eyJ", StringComparison.Ordinal), 18, "BEARER_TOKEN"), span);
    }

    [Fact]
    public void FindSpans_PemBlock_CoversHeaderThroughEndMarker()
    {
        var text = "key:\n" + Pem + "\nafter";
        var span = Assert.Single(new CredentialExposureDetector().FindSpans(text));
        Assert.Equal(new RedactionSpan(5, Pem.Length, "PRIVATE_KEY"), span);
    }

    [Fact]
    public void FindSpans_PemWithoutEndMarker_RunsToEndOfText()
    {
        const string text = "x -----BEGIN PRIVATE KEY-----\nMIIEvQ\nmore";
        var span = Assert.Single(new CredentialExposureDetector().FindSpans(text));
        Assert.Equal(new RedactionSpan(2, text.Length - 2, "PRIVATE_KEY"), span);
    }

    [Fact]
    public void FindSpans_BarePrefixedTokens()
    {
        var text = $"a {GhToken} b {SkToken}";
        var spans = new CredentialExposureDetector().FindSpans(text);
        Assert.Equal(2, spans.Count);
        Assert.Equal(new RedactionSpan(2, GhToken.Length, "GITHUB_TOKEN"), spans[0]);
        Assert.Equal(new RedactionSpan(text.IndexOf("sk-", StringComparison.Ordinal), SkToken.Length, "API_KEY"), spans[1]);
    }

    [Fact]
    public void FindSpans_KeyAssignedBareToken_ReturnsSingleOutermostSpan()
    {
        var text = $"api_key={SkToken}";
        var span = Assert.Single(new CredentialExposureDetector().FindSpans(text));
        Assert.Equal(new RedactionSpan(8, SkToken.Length, "API_KEY"), span);
    }

    [Fact]
    public void FindSpans_CleanText_ReturnsEmpty()
        => Assert.Empty(new CredentialExposureDetector().FindSpans("nothing secret here"));

    [Theory]
    [InlineData("password: hunter2xyz", "hunter2xyz")]
    [InlineData("api_key=abc123def456", "abc123def456")]
    [InlineData("secret-key: zzTopSecret99", "zzTopSecret99")]
    [InlineData("Authorization: Bearer eyJhbGciOi.abc.def", "eyJhbGciOi.abc.def")]
    [InlineData("AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENG", "wJalrXUtnFEMIK7MDENG")]
    [InlineData("ghp_abcdefghijklmnopqrstuvwxyz0123456789", "ghp_abcdefghijklmnopqrstuvwxyz0123456789")]
    [InlineData("sk-abcdefghijklmnopqrstuvwxyz012345", "sk-abcdefghijklmnopqrstuvwxyz012345")]
    [InlineData("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA", "MIIEowIBAAKCAQEA")]
    public async Task AnalyzeAsync_Reason_ContainsNoPartOfTheSecret(string text, string value)
    {
        var result = await new CredentialExposureDetector().AnalyzeAsync(Ctx(text), CancellationToken.None);
        Assert.Equal(Severity.Critical, result.Severity);
        Assert.StartsWith("Credential exposure: ", result.Reason);
        for (var i = 0; i + 4 <= value.Length; i++)
            Assert.DoesNotContain(value.Substring(i, 4), result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AnalyzeAsync_Reason_NamesTheEntityType()
    {
        var result = await new CredentialExposureDetector().AnalyzeAsync(Ctx("password: hunter2"), CancellationToken.None);
        Assert.Equal("Credential exposure: PASSWORD", result.Reason);
    }

    [Theory]
    [InlineData("password=\"correct horse battery\"", "correct horse battery", "PASSWORD")]
    [InlineData("password: 'my pass phrase'", "my pass phrase", "PASSWORD")]
    [InlineData("API_KEY=\"abc 123\"", "abc 123", "API_KEY")]
    [InlineData("secret_key='a b'", "a b", "SECRET_KEY")]
    [InlineData("AWS_SECRET_ACCESS_KEY=\"wJal rXUt\"", "wJal rXUt", "AWS_SECRET")]
    [InlineData("password=abc;", "abc", "PASSWORD")]
    [InlineData("password=abc", "abc", "PASSWORD")]
    [InlineData("password=\"abc\"", "abc", "PASSWORD")]
    [InlineData("{\"api_key\": \"abc\", \"x\": 1}", "abc", "API_KEY")]
    [InlineData("\"api_key\": \"abc123\"", "abc123", "API_KEY")]
    [InlineData("{\"password\":\"p w\"}", "p w", "PASSWORD")]
    [InlineData("Authorization: Bearer xyz,", "xyz", "BEARER_TOKEN")]
    [InlineData("(password=abc)", "abc", "PASSWORD")]
    [InlineData("password=a(b)c);", "a(b)c", "PASSWORD")]
    [InlineData("password=\"abc def", "abc def", "PASSWORD")]
    [InlineData("password=\"hunter2", "hunter2", "PASSWORD")]
    [InlineData("password='abc", "abc", "PASSWORD")]
    [InlineData("{\"password\": \"ab\\\"cd\"}", "ab\\\"cd", "PASSWORD")]
    [InlineData("password='it\\'s'", "it\\'s", "PASSWORD")]
    [InlineData("my password: hunter2.", "hunter2", "PASSWORD")]
    [InlineData("password=(abc)", "abc", "PASSWORD")]
    [InlineData("password=[abc]", "abc", "PASSWORD")]
    [InlineData("password: hunter2\nnext: line", "hunter2", "PASSWORD")]
    [InlineData("password=\"abc\\\r\nnext", "abc", "PASSWORD")]
    [InlineData("\"password\":\n  \"abc\"", "abc", "PASSWORD")]
    [InlineData("password:\r\n  'abc def'", "abc def", "PASSWORD")]
    [InlineData("\"Authorization\": \"Bearer xyz\"", "xyz", "BEARER_TOKEN")]
    [InlineData("[\"PATH=/bin\",\"password=abc\",\"TZ=UTC\"]", "abc", "PASSWORD")]
    [InlineData("password=abc\"def", "abc\"def", "PASSWORD")]
    [InlineData("password=abc\"", "abc", "PASSWORD")]
    public void FindSpans_QuotesAndPunctuation_SpanCoversExactSecret(string text, string value, string entity)
    {
        var span = Assert.Single(new CredentialExposureDetector().FindSpans(text));
        Assert.Equal(entity, span.EntityType);
        Assert.Equal(value, text.Substring(span.Start, span.Length));
    }

    // A closed quoted value may span lines, as a JSON string holding a line break does in the scan text; otherwise
    // only its first line would be redacted and the rest would reach the model.
    [Theory]
    [InlineData("\"password\": \"line1\nline2\"", "line1\nline2")]
    [InlineData("\"password\": \"line1\r\nline2\"", "line1\r\nline2")]
    [InlineData("{\"password\": \"line1\nline2\", \"n\": 1}", "line1\nline2")]
    [InlineData("password=\"a\\\"b\nc\"", "a\\\"b\nc")]
    public void FindSpans_ClosedQuotedValue_SpansLines(string text, string value)
    {
        var span = Assert.Single(new CredentialExposureDetector().FindSpans(text));
        Assert.Equal("PASSWORD", span.EntityType);
        Assert.Equal(value, text.Substring(span.Start, span.Length));
    }

    // A bare JSON literal is no secret: {"password": null} names no password.
    [Theory]
    [InlineData("{\"password\": null}")]
    [InlineData("{\"password\": true, \"n\": 1}")]
    [InlineData("{\"api_key\": false}")]
    [InlineData("password=NULL")]
    [InlineData("secret_key: True;")]
    public async Task JsonLiteral_IsNotASecret(string text)
    {
        var detector = new CredentialExposureDetector();
        Assert.Empty(detector.FindSpans(text));
        Assert.Equal(Severity.None, (await detector.AnalyzeAsync(Ctx(text), CancellationToken.None)).Severity);
    }

    [Theory]
    [InlineData("password: nullify123", "nullify123")]
    [InlineData("password=truefalse9", "truefalse9")]
    [InlineData("api_key=false-positive-7", "false-positive-7")]
    [InlineData("password: \"null\"", "null")]
    public void UnquotedSecret_StartingLikeALiteral_StillMatches(string text, string value)
    {
        var span = Assert.Single(new CredentialExposureDetector().FindSpans(text));
        Assert.Equal(value, text.Substring(span.Start, span.Length));
    }

    // An unclosed quote still ends at its line: the next line's opening quote never closes it.
    [Fact]
    public void FindSpans_UnclosedQuotesOnTwoLines_EachLineItsOwnSecret()
    {
        const string text = "password: \"abc\npassword: \"def";
        var spans = new CredentialExposureDetector().FindSpans(text);
        Assert.Equal(["abc", "def"], spans.Select(s => text.Substring(s.Start, s.Length)), StringComparer.Ordinal);
    }

    [Theory]
    [InlineData("password:\n  min_length: 8")]
    [InlineData("password:\r\nnext")]
    public void FindSpans_ValueOnNextLine_IsNotTakenAsTheSecret(string text)
        => Assert.Empty(new CredentialExposureDetector().FindSpans(text));

    [Fact]
    public async Task AnalyzeAsync_UnterminatedQuote_IsStillCritical()
    {
        var result = await new CredentialExposureDetector().AnalyzeAsync(Ctx("password=\"x"), CancellationToken.None);
        Assert.Equal(Severity.Critical, result.Severity);
    }

    [Theory]
    [InlineData("GHP_abcdefghijklmnopqrstuvwxyz0123456789", "GITHUB_TOKEN")]
    [InlineData("SK-abcdefghijklmnopqrstuvwxyz012345", "API_KEY")]
    public void FindSpans_PrefixedTokens_AreCaseInsensitive(string text, string entity)
    {
        var span = Assert.Single(new CredentialExposureDetector().FindSpans(text));
        Assert.Equal(new RedactionSpan(0, text.Length, entity), span);
    }

    [Theory]
    [InlineData("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaA==\n-----END OPENSSH PRIVATE KEY-----")]
    [InlineData("-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIFHDBO\n-----END ENCRYPTED PRIVATE KEY-----")]
    public void FindSpans_OpensshAndEncryptedPem_CoverWholeBlock(string pem)
    {
        var text = "k " + pem + " tail";
        var span = Assert.Single(new CredentialExposureDetector().FindSpans(text));
        Assert.Equal(new RedactionSpan(2, pem.Length, "PRIVATE_KEY"), span);
    }

    [Fact]
    public async Task AnalyzeAsync_BearerWithSkToken_ReportsBearerFirst()
    {
        var result = await new CredentialExposureDetector().AnalyzeAsync(
            Ctx($"Authorization: Bearer {SkToken}"), CancellationToken.None);
        Assert.Equal("Credential exposure: BEARER_TOKEN", result.Reason);
    }

    [Theory]
    [InlineData("password: hunter2", true)]
    [InlineData("password=\"a b c\"", true)]
    [InlineData("\"api_key\": \"abc\"", true)]
    [InlineData("Authorization: Bearer xyz", true)]
    [InlineData("AWS_SECRET_ACCESS_KEY=abc", true)]
    [InlineData("-----BEGIN RSA PRIVATE KEY-----", true)]
    [InlineData("ghp_abcdefghijklmnopqrstuvwxyz0123456789", true)]
    [InlineData("sk-abcdefghijklmnopqrstuvwxyz012345", true)]
    [InlineData("the password is long and secret", false)]
    [InlineData("nothing to see", false)]
    public async Task AnalyzeAsync_AndFindSpans_AgreeOnTheSameInput(string text, bool expectHit)
    {
        var detector = new CredentialExposureDetector();
        var result = await detector.AnalyzeAsync(Ctx(text), CancellationToken.None);
        var spans = detector.FindSpans(text);
        Assert.Equal(expectHit, result.Severity != Severity.None);
        Assert.Equal(expectHit, spans.Count > 0);
    }

    // A redacted request must not trip the detector that redacted it: a placeholder the current call minted
    // is not a secret. Placeholders have the form [TYPE_n_tag].
    [Theory]
    [InlineData("api_key=[API_KEY_1_k3f9x2]", "[API_KEY_1_k3f9x2]")]
    [InlineData("password: [PASSWORD_12_k3f9x2]", "[PASSWORD_12_k3f9x2]")]
    [InlineData("password=\"[PASSWORD_1_k3f9x2]\"", "[PASSWORD_1_k3f9x2]")]
    [InlineData("Authorization: Bearer [BEARER_TOKEN_1_k3f9x2]", "[BEARER_TOKEN_1_k3f9x2]")]
    [InlineData("AWS_SECRET_ACCESS_KEY=[AWS_SECRET_3_k3f9x2]", "[AWS_SECRET_3_k3f9x2]")]
    [InlineData("api_key=[[API_KEY_2_k3f9x2]]", "[API_KEY_2_k3f9x2]")]
    public async Task MintedPlaceholder_IsNotFlagged(string text, string minted)
    {
        var ctx = new SentinelContext(new AgentId("a"), new AgentId("b"), SessionId.New(),
            new List<ChatMessage> { new(ChatRole.User, text) }, new List<AuditEntry>())
        {
            RedactionPlaceholders = new HashSet<string>(StringComparer.Ordinal) { minted },
        };
        Assert.Equal(Severity.None, (await new CredentialExposureDetector().AnalyzeAsync(ctx, CancellationToken.None)).Severity);
    }

    // Tokens from the redacted request are exempt only for a detector that redacted that request.
    [Theory]
    [InlineData(true, Severity.None)]
    [InlineData(false, Severity.Critical)]
    public async Task RequestPlaceholder_IsExemptOnlyWhenThisDetectorRedacted(bool detectorRedacted, Severity expected)
    {
        var ctx = new SentinelContext(new AgentId("a"), new AgentId("b"), SessionId.New(),
            new List<ChatMessage> { new(ChatRole.Assistant, "password=[ADMIN_99_k3f9x2]") }, new List<AuditEntry>())
        {
            RequestPlaceholders = new HashSet<string>(StringComparer.Ordinal) { "[ADMIN_99_k3f9x2]" },
            RedactingDetectorIds = detectorRedacted
                ? new HashSet<string>(StringComparer.Ordinal) { "SEC-02" }
                : new HashSet<string>(StringComparer.Ordinal) { "SEC-23" },
        };
        Assert.Equal(expected, (await new CredentialExposureDetector().AnalyzeAsync(ctx, CancellationToken.None)).Severity);
    }

    // Only the call's own placeholders are exempt: a real secret that looks like one is still a secret, on
    // every surface, including those that never redact and so mint nothing.
    [Theory]
    [InlineData("password=[ADMIN_99]", "ADMIN_99")]
    [InlineData("password=\"[WINTER_2024]\"", "[WINTER_2024]")]
    [InlineData("api_key=[API_KEY_1]", "API_KEY_1")]
    [InlineData("api_key=[API_KEY_1_k3f9x2]", "API_KEY_1_k3f9x2")]
    public async Task PlaceholderShapedValue_NotMinted_IsDetectedAndRedacted(string text, string value)
    {
        var detector = new CredentialExposureDetector();
        Assert.Equal(Severity.Critical, (await detector.AnalyzeAsync(Ctx(text), CancellationToken.None)).Severity);
        var span = Assert.Single(detector.FindSpans(text));
        Assert.Equal(value, text.Substring(span.Start, span.Length));
    }

    [Theory]
    [InlineData("api_key=[API_KEY_1]x", "API_KEY_1]x")]
    [InlineData("api_key=[api_key_1]", "api_key_1")]
    [InlineData("password=[PASSWORD]", "PASSWORD")]
    [InlineData("api_key=[API_KEY_1_K3F9X2]", "API_KEY_1_K3F9X2")]
    [InlineData("api_key=[API_KEY_1_k3f9x]", "API_KEY_1_k3f9x")]
    public void PlaceholderLookalike_IsStillRedacted(string text, string value)
    {
        var span = Assert.Single(new CredentialExposureDetector().FindSpans(text));
        Assert.Equal(value, text.Substring(span.Start, span.Length));
    }

    // Credentials in environments, .env files and OAuth configs are mostly named *_SECRET or *_TOKEN.
    [Theory]
    [InlineData("APP_CLIENT_SECRET=Zq8vR2kLp9XwT4mN", "Zq8vR2kLp9XwT4mN", "SECRET")]
    [InlineData("client_secret: Zq8vR2kLp9XwT4mN", "Zq8vR2kLp9XwT4mN", "SECRET")]
    [InlineData("{\"client_secret\": \"Zq8v R2kL\"}", "Zq8v R2kL", "SECRET")]
    [InlineData("WEBHOOK_SECRET=\"abc\"", "abc", "SECRET")]
    [InlineData("secret: abc123", "abc123", "SECRET")]
    [InlineData("API_TOKEN=Zq8vR2kLp9XwT4mN", "Zq8vR2kLp9XwT4mN", "TOKEN")]
    [InlineData("SERVICE_AUTH_TOKEN: abc", "abc", "TOKEN")]
    [InlineData("access_token=eyJhbGciOi.abc", "eyJhbGciOi.abc", "TOKEN")]
    [InlineData("{\"refresh_token\": \"abc\"}", "abc", "TOKEN")]
    [InlineData("id_token: abc", "abc", "TOKEN")]
    [InlineData("Session-Token: abc", "abc", "TOKEN")]
    public void FindSpans_SecretAndTokenKeys_CoverValueOnly(string text, string value, string entity)
    {
        var span = Assert.Single(new CredentialExposureDetector().FindSpans(text));
        Assert.Equal(entity, span.EntityType);
        Assert.Equal(value, text.Substring(span.Start, span.Length));
    }

    // Names that end in token or secret but hold no credential, and keys the older patterns already name.
    [Theory]
    [InlineData("max_tokens: 4096")]
    [InlineData("\"next_page_token\": \"abc\"")]
    [InlineData("tokens=12")]
    [InlineData("token_count: 7")]
    [InlineData("csrf_token_name: x")]
    [InlineData("secrets: 3")]
    [InlineData("has_secret: true")]
    [InlineData("SECRET_NAME=db-password")]
    public void FindSpans_NonCredentialTokenAndSecretNames_ReturnEmpty(string text)
        => Assert.Empty(new CredentialExposureDetector().FindSpans(text));

    [Theory]
    [InlineData("secret_key = s3cr3t", "SECRET_KEY")]
    [InlineData("AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI", "AWS_SECRET")]
    [InlineData("Authorization: Bearer abc", "BEARER_TOKEN")]
    public void FindSpans_OlderKeyPatterns_KeepTheirEntityType(string text, string entity)
        => Assert.Equal(entity, Assert.Single(new CredentialExposureDetector().FindSpans(text)).EntityType);

    // A KEY=value string inside a JSON string reads as KEY=value\" in the scan text. The backslash escapes the
    // closing quote, so it is not part of the value; covering it would cover the quote as well.
    [Theory]
    [InlineData("\"Env\": \"[\\\"AWS_SECRET_ACCESS_KEY=wJalrXUt\\\", \\\"TZ=UTC\\\"]\"", "wJalrXUt")]
    [InlineData("\"text\": \"API_TOKEN=abc\\\"\"", "abc")]
    [InlineData("\"text\": \"x password=abc\\\\\"", "abc")]
    public void FindSpans_UnquotedValueBeforeEscapedQuote_ExcludesTheBackslash(string text, string value)
    {
        var span = Assert.Single(new CredentialExposureDetector().FindSpans(text));
        Assert.Equal(value, text.Substring(span.Start, span.Length));
    }

    // A JSON document held in a JSON string, such as a tool's text block, escapes its own quotes: the scan text
    // reads \"password\": \"abc\". The key is still recognised, and the span covers the value between the escaped
    // quotes, not the quotes themselves.
    [Theory]
    [InlineData("\"text\": \"{\\\"password\\\": \\\"hunter2\\\"}\"", "hunter2", "PASSWORD")]
    [InlineData("\"text\": \"{\\\"client_secret\\\":\\\"Zq8v R2kL\\\", \\\"n\\\": 1}\"", "Zq8v R2kL", "SECRET")]
    [InlineData("\"text\": \"{\\\"access_token\\\": \\\"a\\\\\\\\b\\\"}\"", "a\\\\\\\\b", "TOKEN")]
    public void FindSpans_KeyInsideAnEscapedJsonDocument_CoversTheValueBetweenTheEscapedQuotes(string text, string value, string entity)
    {
        var span = Assert.Single(new CredentialExposureDetector().FindSpans(text));
        Assert.Equal(entity, span.EntityType);
        Assert.Equal(value, text.Substring(span.Start, span.Length));
    }

    // Inside an escaped JSON document: an empty value names no secret, a truncated one is covered to the end of
    // the line, and an escaped quote inside the value stays in it.
    [Theory]
    [InlineData("""
        "text": "{\"password\": \"\", \"user\": \"bob\"}"
        """, null)]
    [InlineData("""
        "text": "{\"password\": \"hunter2
        """, "hunter2")]
    [InlineData("""
        "body": "{\"password\": \"pa\\\"ss\"}"
        """, """
        pa\\\"ss
        """)]
    public void FindSpans_EscapedJsonValueEdgeCases(string text, string? value)
    {
        var spans = new CredentialExposureDetector().FindSpans(text);
        if (value is null)
        {
            Assert.Empty(spans);
            return;
        }
        var span = Assert.Single(spans);
        Assert.Equal(value, text.Substring(span.Start, span.Length));
    }

    // References, placeholders and type names stand where a secret would, but are none.
    [Theory]
    [InlineData("id-token: write")]
    [InlineData("GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}")]
    [InlineData("client_secret: ${{ secrets.X }}")]
    [InlineData("NPM_TOKEN=${NPM_TOKEN}")]
    [InlineData("password: ${DB_PASSWORD}")]
    [InlineData("secret=$(cat file)")]
    [InlineData("accessToken: string;")]
    [InlineData("refresh_token: str")]
    [InlineData("access_token: Optional[str] = None")]
    [InlineData("""MY_TOKEN: str = os.environ["MY_TOKEN"]""")]
    [InlineData("const secret = process.env.SECRET;")]
    [InlineData("""if secret == "abc":""")]
    [InlineData("""api_token = "<your-token>" """)]
    [InlineData("ACCESS_TOKEN=your_access_token_here")]
    [InlineData("""password = getenv("DB_PASSWORD")""")]
    [InlineData("""password = os.getenv("DB_PASSWORD")""")]
    [InlineData("""secret = ENV["APP_SECRET"]""")]
    [InlineData("""client_secret = Environment.GetEnvironmentVariable("X")""")]
    [InlineData("""{"password": "${DB_PASSWORD}"}""")]
    public void FindSpans_ReferencesPlaceholdersAndTypeNames_ReturnEmpty(string text)
        => Assert.Empty(new CredentialExposureDetector().FindSpans(text));

    // A secret that only starts like a reference, a placeholder or a comparison is still a secret: the shape
    // has to be the whole value, and inside quotes an = is never a comparison.
    [Theory]
    [InlineData("""{"password": "=Kx9#mQ2vL"}""", "=Kx9#mQ2vL")]
    [InlineData("""password: "=Kx9#mQ2vL" """, "=Kx9#mQ2vL")]
    [InlineData("""
        "text": "{\"password\":\"=abc\"}"
        """, "=abc")]
    [InlineData("""{"password": "$(Kx9mQ"}""", "$(Kx9mQ")]
    [InlineData("""{"password": "${Kx9"}""", "${Kx9")]
    [InlineData("""{"password": "<Rt5>Kx9mQ"}""", "<Rt5>Kx9mQ")]
    [InlineData("password: <Kx9#$%^&*()_+mQ2vL>", "<Kx9#$%^&*()_+mQ2vL>")]
    public void FindSpans_SecretThatStartsLikeAReference_IsCovered(string text, string value)
    {
        var span = Assert.Single(new CredentialExposureDetector().FindSpans(text));
        Assert.Equal(value, text.Substring(span.Start, span.Length));
    }

    [Theory]
    [InlineData("""{"IdToken": "eyJhbGciOi.abc"}""", "eyJhbGciOi.abc")]
    [InlineData("idToken: abc", "abc")]
    public void FindSpans_CamelCaseIdToken_CoversValue(string text, string value)
    {
        var span = Assert.Single(new CredentialExposureDetector().FindSpans(text));
        Assert.Equal("TOKEN", span.EntityType);
        Assert.Equal(value, text.Substring(span.Start, span.Length));
    }

    // The .NET and JavaScript spelling of a secret key.
    [Theory]
    [InlineData("""{"AzureAd": {"ClientSecret": "abc"}}""", "abc")]
    [InlineData("clientSecret: abc123", "abc123")]
    public void FindSpans_CamelCaseSecretKey_CoversValue(string text, string value)
    {
        var span = Assert.Single(new CredentialExposureDetector().FindSpans(text));
        Assert.Equal("SECRET", span.EntityType);
        Assert.Equal(value, text.Substring(span.Start, span.Length));
    }

    [Fact]
    public void Secrets_AreNeverRestoredIntoToolArguments()
        => Assert.False(((IRedactingDetector)new CredentialExposureDetector()).RestoreIntoToolArguments);

    [Fact]
    public void Pii_IsRestoredIntoToolArguments()
        => Assert.True(((IRedactingDetector)new PiiLeakageDetector()).RestoreIntoToolArguments);
}
