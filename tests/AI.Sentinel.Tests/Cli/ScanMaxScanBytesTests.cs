using AI.Sentinel.Cli;
using AI.Sentinel.Tests.Helpers;
using Xunit;

namespace AI.Sentinel.Tests.Cli;

/// <summary><c>sentinel scan --max-scan-bytes</c> sets the scan budget of the replay, so a turn over it is reported
/// as <c>SEC-00</c> as the hooks and the MCP proxy report it (#439).</summary>
public class ScanMaxScanBytesTests
{
    // 30 bytes of user text, then a 31-byte reply: both under the default, both over a 10-byte budget.
    private static readonly string Fixture =
        Path.Combine(AppContext.BaseDirectory, "Fixtures", "conversations", "clean-openai.json");

    private static Task<int> ScanAsync(StringWriter stderr, int? maxScanBytes) =>
        ScanCommand.RunAsync(
            Fixture, ConversationFormat.Auto, OutputFormat.Text, new StringWriter(), stderr,
            TestContext.Current.CancellationToken,
            expectedDetectors: ["SEC-00"],
            embeddingGenerator: new ExactMatchEmbeddingGenerator(),
            maxScanBytes: maxScanBytes);

    [Fact]
    public async Task Scan_DefaultBudget_DoesNotReportSec00()
    {
        var stderr = new StringWriter();

        Assert.Equal(1, await ScanAsync(stderr, maxScanBytes: null));
        Assert.Contains("SEC-00", stderr.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Scan_SmallBudget_ReportsSec00()
    {
        var stderr = new StringWriter();

        Assert.Equal(0, await ScanAsync(stderr, maxScanBytes: 10));
        Assert.DoesNotContain("Assertion failed", stderr.ToString(), StringComparison.Ordinal);
    }

    private static async Task<(int Exit, string Stderr)> InvokeAsync(params string[] args)
    {
        var stderr = new StringWriter();
        var root = new System.CommandLine.RootCommand { ScanCommand.Build() };
        var exit = await root.Parse(["scan", Fixture, .. args]).InvokeAsync(
            new System.CommandLine.InvocationConfiguration { Output = new StringWriter(), Error = stderr },
            TestContext.Current.CancellationToken);
        return (exit, stderr.ToString());
    }

    [Fact]
    public async Task Scan_MaxScanBytesFlag_ReachesThePipeline()
    {
        Assert.Equal(0, (await InvokeAsync("--max-scan-bytes", "10", "--expect", "SEC-00")).Exit);
        Assert.Equal(1, (await InvokeAsync("--expect", "SEC-00")).Exit);
    }

    [Theory]
    [InlineData("0")]
    [InlineData("-1")]
    public async Task Scan_NonPositiveMaxScanBytes_IsAnError(string value)
    {
        var (exit, stderr) = await InvokeAsync("--max-scan-bytes", value);

        Assert.NotEqual(0, exit);
        Assert.Contains("--max-scan-bytes must be a positive number of bytes.", stderr, StringComparison.Ordinal);
    }
}
