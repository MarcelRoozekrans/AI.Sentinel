using AI.Sentinel.Cli;
using AI.Sentinel.Detection;
using Xunit;

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
            default);

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
            default);

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
            default);

        Assert.Equal(2, exit);
    }

    [Fact]
    public async Task Scan_AutoDetectFails_ExitsTwo()
    {
        var tempFile = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(tempFile, "not json at all");
            var stdout = new StringWriter();
            var stderr = new StringWriter();

            var exit = await ScanCommand.RunAsync(
                tempFile,
                ConversationFormat.Auto,
                OutputFormat.Text,
                stdout,
                stderr,
                default);

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
            default,
            expectedDetectors: ["SEC-01"]);

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
            default,
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
            default,
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
            await File.WriteAllTextAsync(tempBaseline, JsonFormatter.Format(baseline));

            var stdout = new StringWriter();
            var stderr = new StringWriter();

            var exit = await ScanCommand.RunAsync(
                Fixture("clean-openai.json"),
                ConversationFormat.Auto,
                OutputFormat.Text,
                stdout,
                stderr,
                default,
                baselinePath: tempBaseline);

            Assert.Equal(1, exit);
        }
        finally
        {
            File.Delete(tempBaseline);
        }
    }
}
