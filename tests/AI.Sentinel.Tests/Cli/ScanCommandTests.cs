using AI.Sentinel.Cli;
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
}
