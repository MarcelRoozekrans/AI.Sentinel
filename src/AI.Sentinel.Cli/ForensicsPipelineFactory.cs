using Microsoft.Extensions.AI;
using Microsoft.Extensions.DependencyInjection;
using AI.Sentinel.Detection;

namespace AI.Sentinel.Cli;

/// <summary>
/// Builds a <see cref="SentinelPipeline"/> configured for offline forensics replay.
/// </summary>
/// <remarks>
/// All severities are mapped to <see cref="SentinelAction.Quarantine"/> so that every detection
/// surfaces through the <c>Result.Failure</c> channel. <c>Log</c> / <c>Alert</c> / <c>PassThrough</c>
/// actions would suppress detections from <see cref="ReplayRunner"/>'s view. In forensics mode the
/// "Quarantine" semantics are not about blocking real LLM calls — they are about reporting.
/// </remarks>
public static class ForensicsPipelineFactory
{
    /// <summary>Builds a service provider + pipeline wired for forensics replay using the supplied inner chat client.</summary>
    /// <returns>The provider (for disposal) and the pipeline.</returns>
    public static (ServiceProvider Provider, SentinelPipeline Pipeline) Build(
        IChatClient innerClient,
        IEmbeddingGenerator<string, Embedding<float>>? embeddingGenerator = null)
    {
        ArgumentNullException.ThrowIfNull(innerClient);

        var services = new ServiceCollection();
        services.AddAISentinel(opts =>
        {
            opts.OnCritical = SentinelAction.Quarantine;
            opts.OnHigh = SentinelAction.Quarantine;
            opts.OnMedium = SentinelAction.Quarantine;
            opts.OnLow = SentinelAction.Quarantine;
            opts.EmbeddingGenerator = embeddingGenerator;
        });
        var provider = services.BuildServiceProvider();
        var pipeline = provider.BuildSentinelPipeline(innerClient);
        return (provider, pipeline);
    }
}
