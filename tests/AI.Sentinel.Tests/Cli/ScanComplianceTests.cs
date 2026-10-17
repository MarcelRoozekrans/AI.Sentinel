using AI.Sentinel.Cli;
using Xunit;
using AI.Sentinel.Tests.Helpers;

namespace AI.Sentinel.Tests.Cli;

/// <summary><c>sentinel scan</c> runs the opt-in compliance detectors only with <c>--compliance</c> or
/// <c>SENTINEL_HOOK_COMPLIANCE=on</c>; otherwise <c>--expect CMP-03</c> fails. Non-parallel because one case
/// sets an environment variable that the others must not see.</summary>
[Collection("NonParallel")]
public class ScanComplianceTests
{
    private static readonly string Fixture =
        Path.Combine(AppContext.BaseDirectory, "Fixtures", "conversations", "compliance-openai.json");

    private static Task<int> ScanAsync(StringWriter stderr, bool enableComplianceDetectors) =>
        ScanCommand.RunAsync(
            Fixture, ConversationFormat.Auto, OutputFormat.Text, new StringWriter(), stderr,
            TestContext.Current.CancellationToken,
            expectedDetectors: ["CMP-03"],
            embeddingGenerator: new ExactMatchEmbeddingGenerator(),
            enableComplianceDetectors: enableComplianceDetectors);

    [Fact]
    public async Task Scan_WithoutTheSwitch_DoesNotRunTheComplianceDetectors()
    {
        var stderr = new StringWriter();

        var exit = await ScanAsync(stderr, enableComplianceDetectors: false);

        Assert.Equal(1, exit);
        Assert.Contains("CMP-03", stderr.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Scan_WithComplianceFlag_RunsThem()
    {
        var stderr = new StringWriter();

        var exit = await ScanAsync(stderr, enableComplianceDetectors: true);

        Assert.Equal(0, exit);
        Assert.DoesNotContain("Assertion failed", stderr.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Scan_WithHookComplianceVariable_RunsThem()
    {
        Environment.SetEnvironmentVariable("SENTINEL_HOOK_COMPLIANCE", "on");
        try
        {
            var exit = await ScanAsync(new StringWriter(), enableComplianceDetectors: false);

            Assert.Equal(0, exit);
        }
        finally
        {
            Environment.SetEnvironmentVariable("SENTINEL_HOOK_COMPLIANCE", null);
        }
    }

    [Fact]
    public async Task Scan_ComplianceFlag_ReachesThePipeline()
    {
        // With no embedding generator the scan warns how many semantic detectors are inert. The four
        // compliance detectors join that count only when --compliance turned them on.
        static async Task<int> InertCountAsync(params string[] args)
        {
            var stderr = new StringWriter();
            var root = new System.CommandLine.RootCommand { ScanCommand.Build() };
            await root.Parse(["scan", Fixture, .. args]).InvokeAsync(
                new System.CommandLine.InvocationConfiguration { Output = new StringWriter(), Error = stderr },
                TestContext.Current.CancellationToken);
            var warning = stderr.ToString();
            return int.Parse(warning.Split("— ")[1].Split(' ')[0], System.Globalization.CultureInfo.InvariantCulture);
        }

        Assert.Equal(await InertCountAsync() + 4, await InertCountAsync("--compliance"));
    }
}
