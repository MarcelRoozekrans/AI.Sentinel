using AI.Sentinel.Cli;
using AI.Sentinel.Detection;
using Xunit;
using AI.Sentinel.Tests.Helpers;

namespace AI.Sentinel.Tests.Cli;

public class ScanCommandTests
{
    private static string Fixture(string name) =>
        Path.Combine(AppContext.BaseDirectory, "Fixtures", "conversations", name);

    [Fact]
    public async Task Scan_CleanFile_ExitsZero()
    {
        var stdout = new StringWriter();
        var stderr = new StringWriter();

        var exit = await ScanCommand.RunAsync(
            Fixture("clean-openai.json"),
            ConversationFormat.Auto,
            OutputFormat.Text,
            stdout,
            stderr,
            TestContext.Current.CancellationToken);

        Assert.Equal(0, exit);
        Assert.Contains("Clean", stdout.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Scan_OutputJson_EmitsSchemaV1()
    {
        var stdout = new StringWriter();
        var stderr = new StringWriter();

        var exit = await ScanCommand.RunAsync(
            Fixture("clean-openai.json"),
            ConversationFormat.Auto,
            OutputFormat.Json,
            stdout,
            stderr,
            TestContext.Current.CancellationToken);

        Assert.Equal(0, exit);
        Assert.Contains("\"schemaVersion\": \"1\"", stdout.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Scan_FileNotFound_ExitsTwo()
    {
        var stdout = new StringWriter();
        var stderr = new StringWriter();

        var exit = await ScanCommand.RunAsync(
            "does-not-exist.json",
            ConversationFormat.Auto,
            OutputFormat.Text,
            stdout,
            stderr,
            TestContext.Current.CancellationToken);

        Assert.Equal(2, exit);
    }

    [Fact]
    public async Task Scan_AutoDetectFails_ExitsTwo()
    {
        var tempFile = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(tempFile, "not json at all", TestContext.Current.CancellationToken);
            var stdout = new StringWriter();
            var stderr = new StringWriter();

            var exit = await ScanCommand.RunAsync(
                tempFile,
                ConversationFormat.Auto,
                OutputFormat.Text,
                stdout,
                stderr,
                TestContext.Current.CancellationToken);

            Assert.Equal(2, exit);
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    [Fact]
    public async Task Scan_WithExpectFlag_FiresExitsZero()
    {
        var stdout = new StringWriter();
        var stderr = new StringWriter();

        var exit = await ScanCommand.RunAsync(
            Fixture("injection-openai.json"),
            ConversationFormat.Auto,
            OutputFormat.Text,
            stdout,
            stderr,
            TestContext.Current.CancellationToken,
            expectedDetectors: ["SEC-01"],
            embeddingGenerator: new FakeEmbeddingGenerator());

        Assert.Equal(0, exit);
    }

    [Fact]
    public async Task Scan_WithExpectFlag_MissingExitsOne()
    {
        var stdout = new StringWriter();
        var stderr = new StringWriter();

        var exit = await ScanCommand.RunAsync(
            Fixture("clean-openai.json"),
            ConversationFormat.Auto,
            OutputFormat.Text,
            stdout,
            stderr,
            TestContext.Current.CancellationToken,
            expectedDetectors: ["SEC-01"]);

        Assert.Equal(1, exit);
    }

    [Fact]
    public async Task Scan_MinSeverityFail_ExitsOne()
    {
        var stdout = new StringWriter();
        var stderr = new StringWriter();

        var exit = await ScanCommand.RunAsync(
            Fixture("clean-openai.json"),
            ConversationFormat.Auto,
            OutputFormat.Text,
            stdout,
            stderr,
            TestContext.Current.CancellationToken,
            minSeverity: Severity.High);

        Assert.Equal(1, exit);
    }

    [Fact]
    public async Task Scan_BaselineRegression_ExitsOne()
    {
        var baseline = new ReplayResult(
            "1",
            "baseline.json",
            ConversationFormat.OpenAIChatCompletion,
            1,
            [new TurnResult(0, Severity.High,
                [new TurnDetection("SEC-01", Severity.High, "prior match")])],
            Severity.High);

        var tempBaseline = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(tempBaseline, JsonFormatter.Format(baseline), TestContext.Current.CancellationToken);

            var stdout = new StringWriter();
            var stderr = new StringWriter();

            var exit = await ScanCommand.RunAsync(
                Fixture("clean-openai.json"),
                ConversationFormat.Auto,
                OutputFormat.Text,
                stdout,
                stderr,
                TestContext.Current.CancellationToken,
                baselinePath: tempBaseline);

            Assert.Equal(1, exit);
        }
        finally
        {
            File.Delete(tempBaseline);
        }
    }

    [Fact]
    public async Task Scan_BaselineNewDetection_ExitsZero()
    {
        // Baseline: clean (no detections). Current: SEC-01 fires on the injection fixture.
        // A new detection that wasn't in the baseline is informational — should NOT exit non-zero.
        var baseline = new ReplayResult(
            "1",
            "baseline.json",
            ConversationFormat.OpenAIChatCompletion,
            1,
            [new TurnResult(0, Severity.None, [])],
            Severity.None);

        var tempBaseline = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(tempBaseline, JsonFormatter.Format(baseline), TestContext.Current.CancellationToken);

            var stdout = new StringWriter();
            var stderr = new StringWriter();

            var exit = await ScanCommand.RunAsync(
                Fixture("injection-openai.json"),
                ConversationFormat.Auto,
                OutputFormat.Text,
                stdout,
                stderr,
                TestContext.Current.CancellationToken,
                baselinePath: tempBaseline,
                embeddingGenerator: new FakeEmbeddingGenerator());

            Assert.Equal(0, exit);
            Assert.Contains("NEW", stdout.ToString(), StringComparison.Ordinal);
        }
        finally
        {
            File.Delete(tempBaseline);
        }
    }

    /// <summary>#170 — scan reported Clean for conversations containing textbook injections because
    /// every semantic detector was inert, with nothing on stderr to say so.</summary>
    [Fact]
    public async Task Scan_NoEmbeddingGenerator_WarnsOnStderrThatSemanticDetectionIsOff()
    {
        var stdout = new StringWriter();
        var stderr = new StringWriter();

        await ScanCommand.RunAsync(
            Fixture("clean-openai.json"),
            ConversationFormat.Auto,
            OutputFormat.Text,
            stdout,
            stderr,
            TestContext.Current.CancellationToken);

        Assert.Contains("EmbeddingGenerator", stderr.ToString(), StringComparison.Ordinal);
        Assert.Contains("semantic detectors", stderr.ToString(), StringComparison.Ordinal);
    }

    /// <summary>#170 closed with a note that `sentinel scan` "has no option to scan the prompt
    /// direction" because it reported Clean for a conversation whose user turn held a textbook
    /// injection. ReplayRunner does scan the prompt leg — the Clean result was the inert-detector
    /// bug, not a missing option. With SEC-01's rule layer the same fixture is now flagged with no
    /// embedding generator configured, which is what a forensics scan in CI would see.</summary>
    [Fact]
    public async Task Scan_InjectionInTheUserTurn_IsFlagged_WithNoEmbeddingGenerator()
    {
        var stdout = new StringWriter();
        var stderr = new StringWriter();

        var exit = await ScanCommand.RunAsync(
            Fixture("injection-openai.json"),
            ConversationFormat.Auto,
            OutputFormat.Json,
            stdout,
            stderr,
            TestContext.Current.CancellationToken);

        // Exit 0 is correct here: scan reports, and gating is opt-in through --expect /
        // --min-severity. The detection appearing at all is the fix.
        Assert.Contains("SEC-01", stdout.ToString(), StringComparison.Ordinal);
        Assert.Equal(0, exit);
    }

    /// <summary>--min-severity is a positive assertion — "this conversation must contain at least
    /// this severity" — used to regression-test detectors against known-bad fixtures. With SEC-01
    /// inert the scan reported MaxSeverity None, so this assertion failed and the fixture could not
    /// be used that way. It now passes.</summary>
    [Fact]
    public async Task Scan_InjectionInTheUserTurn_SatisfiesAMinSeverityAssertion()
    {
        var stdout = new StringWriter();
        var stderr = new StringWriter();

        var exit = await ScanCommand.RunAsync(
            Fixture("injection-openai.json"),
            ConversationFormat.Auto,
            OutputFormat.Text,
            stdout,
            stderr,
            TestContext.Current.CancellationToken,
            expectedDetectors: null,
            minSeverity: Severity.High);

        Assert.Equal(0, exit);
    }
}
