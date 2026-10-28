namespace AI.Sentinel.Screening;

/// <summary>Screens through a pipeline built on first use, so registering it has no side effects.</summary>
internal sealed class SentinelScreener : ISentinelScreener
{
    private readonly Lazy<SentinelPipeline> _pipeline;

    public SentinelScreener(Func<SentinelPipeline> factory) =>
        _pipeline = new Lazy<SentinelPipeline>(factory, LazyThreadSafetyMode.ExecutionAndPublication);

    public ValueTask<ScreeningOutcome> ScreenAsync(string text, ScreeningOptions? options = null, CancellationToken ct = default) =>
        _pipeline.Value.ScreenAsync(text, options, ct);
}
