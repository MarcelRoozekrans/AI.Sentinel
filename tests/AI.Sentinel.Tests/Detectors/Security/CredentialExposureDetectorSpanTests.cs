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
    [InlineData("password=")]
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
}
