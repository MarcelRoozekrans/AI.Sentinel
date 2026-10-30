using AI.Sentinel.Detection;
using AI.Sentinel.Review;
using Xunit;

namespace AI.Sentinel.Tests.Review;

/// <summary>Reads the CLI review configuration. A malformed setting must name itself rather than
/// leaving the second-stage review quietly off.</summary>
public class SentinelReviewSetupTests
{
    private static Dictionary<string, string?> Env(params (string Key, string? Value)[] entries)
    {
        var env = new Dictionary<string, string?>(StringComparer.Ordinal);
        foreach (var (key, value) in entries) env[key] = value;
        return env;
    }

    private const string Endpoint = "https://api.openai.com/v1/chat/completions";

    [Fact]
    public void NotConfigured_ReturnsNothing_AndReportsNoError()
    {
        var setup = SentinelReviewSetup.TryCreateFromEnvironment(Env(), out var error);

        Assert.Null(setup);
        Assert.Null(error);
    }

    [Fact]
    public void EndpointAndModel_ProduceAnLlmJudgeReviewer_WithNoLimitsSet()
    {
        using var setup = SentinelReviewSetup.TryCreateFromEnvironment(Env(
            ("SENTINEL_REVIEW_ENDPOINT", Endpoint),
            ("SENTINEL_REVIEW_MODEL", "gpt-4o-mini"),
            ("SENTINEL_REVIEW_API_KEY", "sk-test")), out var error);

        Assert.Null(error);
        Assert.NotNull(setup);
        Assert.IsType<LlmJudgeReviewer>(setup!.Reviewer);
        Assert.Null(setup.MaxReviewsPerScan);
        Assert.Null(setup.ReviewTimeout);
    }

    [Fact]
    public void LimitsAreParsed()
    {
        using var setup = SentinelReviewSetup.TryCreateFromEnvironment(Env(
            ("SENTINEL_REVIEW_ENDPOINT", Endpoint),
            ("SENTINEL_REVIEW_MODEL", "m"),
            ("SENTINEL_REVIEW_MAX_PER_SCAN", "0"),
            ("SENTINEL_REVIEW_TIMEOUT_MS", "2500")), out var error);

        Assert.Null(error);
        Assert.Equal(0, setup!.MaxReviewsPerScan);
        Assert.Equal(TimeSpan.FromMilliseconds(2500), setup.ReviewTimeout);
    }

    [Theory]
    [InlineData("SENTINEL_REVIEW_MODEL", null, "SENTINEL_REVIEW_ENDPOINT")]
    [InlineData("SENTINEL_REVIEW_ENDPOINT", Endpoint, "SENTINEL_REVIEW_MODEL")]
    public void HalfConfigured_NamesTheMissingVariable(string present, string? value, string missing)
    {
        var setup = SentinelReviewSetup.TryCreateFromEnvironment(
            Env((present, value ?? "some-model")), out var error);

        Assert.Null(setup);
        Assert.NotNull(error);
        Assert.Contains(missing, error);
    }

    [Theory]
    [InlineData("not a url")]
    [InlineData("/relative/path")]
    [InlineData("ftp://example.invalid/chat")]
    [InlineData("file:///etc/passwd")]
    public void BadEndpoint_NamesTheVariable(string endpoint)
    {
        var setup = SentinelReviewSetup.TryCreateFromEnvironment(Env(
            ("SENTINEL_REVIEW_ENDPOINT", endpoint),
            ("SENTINEL_REVIEW_MODEL", "m")), out var error);

        Assert.Null(setup);
        Assert.Contains("SENTINEL_REVIEW_ENDPOINT", error);
    }

    [Theory]
    [InlineData("abc")]
    [InlineData("-1")]
    [InlineData("1.5")]
    public void BadMaxPerScan_NamesTheVariable(string value)
    {
        var setup = SentinelReviewSetup.TryCreateFromEnvironment(Env(
            ("SENTINEL_REVIEW_ENDPOINT", Endpoint),
            ("SENTINEL_REVIEW_MODEL", "m"),
            ("SENTINEL_REVIEW_MAX_PER_SCAN", value)), out var error);

        Assert.Null(setup);
        Assert.Contains("SENTINEL_REVIEW_MAX_PER_SCAN", error);
    }

    [Theory]
    [InlineData("abc")]
    [InlineData("0")]
    [InlineData("-5")]
    public void BadTimeout_NamesTheVariable(string value)
    {
        var setup = SentinelReviewSetup.TryCreateFromEnvironment(Env(
            ("SENTINEL_REVIEW_ENDPOINT", Endpoint),
            ("SENTINEL_REVIEW_MODEL", "m"),
            ("SENTINEL_REVIEW_TIMEOUT_MS", value)), out var error);

        Assert.Null(setup);
        Assert.Contains("SENTINEL_REVIEW_TIMEOUT_MS", error);
    }

    [Theory]
    [InlineData("ftp://user:pass@example.invalid/x")]
    [InlineData("https://user:pass@")]
    public void BadEndpoint_DoesNotEchoTheValue(string endpoint)
    {
        var setup = SentinelReviewSetup.TryCreateFromEnvironment(Env(
            ("SENTINEL_REVIEW_ENDPOINT", endpoint),
            ("SENTINEL_REVIEW_MODEL", "m")), out var error);

        Assert.Null(setup);
        Assert.DoesNotContain("pass", error, StringComparison.Ordinal);
    }
}
