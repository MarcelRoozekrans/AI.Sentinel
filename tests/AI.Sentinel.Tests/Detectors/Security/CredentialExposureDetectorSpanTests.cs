using System.Diagnostics;
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
    public void FindSpans_QuotesAndPunctuation_SpanCoversExactSecret(string text, string value, string entity)
    {
        var span = Assert.Single(new CredentialExposureDetector().FindSpans(text));
        Assert.Equal(entity, span.EntityType);
        Assert.Equal(value, text.Substring(span.Start, span.Length));
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

    [Theory]
    [InlineData("password=")]
    [InlineData("password=\"")]
    [InlineData("password=\"\\")]
    [InlineData("password=\"a\\\"b")]
    [InlineData("password='a ")]
    [InlineData("api_key=\"x\",")]
    [InlineData("-----BEGIN PRIVATE KEY-----")]
    [InlineData("sk-")]
    [InlineData("Authorization: Bearer ")]
    public void FindSpans_LongAdversarialInput_StaysFast(string unit)
    {
        var text = string.Concat(Enumerable.Repeat(unit, 100_000 / unit.Length));
        var sw = Stopwatch.StartNew();
        _ = new CredentialExposureDetector().FindSpans(text);
        Assert.True(sw.ElapsedMilliseconds < 1000, $"took {sw.ElapsedMilliseconds} ms");
    }

    // A redacted request must not trip the detector that redacted it: the placeholder is not a secret.
    [Theory]
    [InlineData("api_key=[API_KEY_1]")]
    [InlineData("password: [PASSWORD_12]")]
    [InlineData("password=\"[PASSWORD_1]\"")]
    [InlineData("Authorization: Bearer [BEARER_TOKEN_1]")]
    [InlineData("AWS_SECRET_ACCESS_KEY=[AWS_SECRET_3]")]
    public async Task PlaceholderValue_IsNotASecret(string text)
    {
        var detector = new CredentialExposureDetector();
        Assert.Empty(detector.FindSpans(text));
        Assert.Equal(Severity.None, (await detector.AnalyzeAsync(Ctx(text), CancellationToken.None)).Severity);
    }

    [Theory]
    [InlineData("api_key=[API_KEY_1]x", "API_KEY_1]x")]
    [InlineData("api_key=[api_key_1]", "api_key_1")]
    [InlineData("password=[PASSWORD]", "PASSWORD")]
    public void PlaceholderLookalike_IsStillRedacted(string text, string value)
    {
        var span = Assert.Single(new CredentialExposureDetector().FindSpans(text));
        Assert.Equal(value, text.Substring(span.Start, span.Length));
    }

    [Fact]
    public void Secrets_AreNeverRestoredIntoToolArguments()
        => Assert.False(((IRedactingDetector)new CredentialExposureDetector()).RestoreIntoToolArguments);

    [Fact]
    public void Pii_IsRestoredIntoToolArguments()
        => Assert.True(((IRedactingDetector)new PiiLeakageDetector()).RestoreIntoToolArguments);
}
