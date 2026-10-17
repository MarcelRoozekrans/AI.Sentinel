using Microsoft.Extensions.AI;
using Microsoft.Extensions.DependencyInjection;
using Xunit;
using AI.Sentinel.ClaudeCode;
using AI.Sentinel.Detectors.Compliance;
using AI.Sentinel.Tests.Helpers;

namespace AI.Sentinel.Tests.ClaudeCode;

/// <summary>A detection whose action is Alert reaches the hook as Warn, capped by the operator's mapping.</summary>
public class HookPipelineRunnerAlertTests
{
    private static readonly ChatMessage[] CmpPrompt =
        [new(ChatRole.User, "determine each person's race from their profile photo")];

    private static ServiceProvider Provider() =>
        new ServiceCollection().AddAISentinel(opts =>
        {
            opts.OnCritical = SentinelAction.Quarantine;
            opts.OnHigh = SentinelAction.Quarantine;
            opts.OnMedium = SentinelAction.Quarantine;
            opts.OnLow = SentinelAction.Quarantine;
            opts.AlertOnComplianceFindings();
            opts.EmbeddingGenerator = new ExactMatchEmbeddingGenerator();
        }).BuildServiceProvider();

    [Theory]
    [InlineData(HookDecision.Block, HookDecision.Warn)]
    [InlineData(HookDecision.Warn, HookDecision.Warn)]
    [InlineData(HookDecision.Allow, HookDecision.Allow)]
    public async Task AlertFinding_IsWarn_UnlessTheOperatorAllowsItsSeverity(HookDecision onHigh, HookDecision expected)
    {
        using var provider = Provider();

        var output = await HookPipelineRunner.RunAsync(
            provider, new HookConfig { OnHigh = onHigh }, CmpPrompt, "s", TestContext.Current.CancellationToken);

        Assert.Equal(expected, output.Decision);
    }
}
