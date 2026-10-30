using AI.Sentinel.Cli;
using AI.Sentinel.Tests.Helpers;
using Xunit;

namespace AI.Sentinel.Tests.Cli;

[Collection("NonParallel")]
public class ScanReviewTests
{
    private static string Fixture(string name) =>
        Path.Combine(AppContext.BaseDirectory, "Fixtures", "conversations", name);

    [Fact]
    public async Task ScanCommand_ReadsReviewEnvironment()
    {
        var previous = Environment.GetEnvironmentVariable("SENTINEL_REVIEW_MODEL");
        Environment.SetEnvironmentVariable("SENTINEL_REVIEW_MODEL", "some-model");
        try
        {
            var stderr = new StringWriter();

            var exit = await ScanCommand.RunAsync(
                Fixture("clean-openai.json"), ConversationFormat.Auto, OutputFormat.Text,
                new StringWriter(), stderr, TestContext.Current.CancellationToken);

            Assert.Equal(0, exit);
            Assert.Contains("SENTINEL_REVIEW_ENDPOINT", stderr.ToString(), StringComparison.Ordinal);
        }
        finally
        {
            Environment.SetEnvironmentVariable("SENTINEL_REVIEW_MODEL", previous);
        }
    }

    [Fact]
    public async Task Scan_WithGeneratorAndNoReviewer_WarnsThatSemanticDetectionsAreCapped()
    {
        var stderr = new StringWriter();

        await ScanCommand.RunAsync(
            Fixture("clean-openai.json"), ConversationFormat.Auto, OutputFormat.Text,
            new StringWriter(), stderr, TestContext.Current.CancellationToken,
            embeddingGenerator: new FakeEmbeddingGenerator());

        Assert.Contains("capped at Medium", stderr.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Scan_WithReviewer_DoesNotWarnThatSemanticDetectionsAreCapped()
    {
        var stderr = new StringWriter();

        await ScanCommand.RunAsync(
            Fixture("clean-openai.json"), ConversationFormat.Auto, OutputFormat.Text,
            new StringWriter(), stderr, TestContext.Current.CancellationToken,
            embeddingGenerator: new FakeEmbeddingGenerator(),
            reviewer: new FixedVerdictReviewer(AI.Sentinel.Detection.Severity.High));

        Assert.DoesNotContain("capped at Medium", stderr.ToString(), StringComparison.Ordinal);
    }
}
