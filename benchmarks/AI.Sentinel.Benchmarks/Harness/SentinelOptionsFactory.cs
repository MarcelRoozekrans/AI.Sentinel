using AI.Sentinel;

namespace AI.Sentinel.Benchmarks.Harness;

/// <summary>Three option presets shared by all benchmarks.</summary>
internal static class SentinelOptionsFactory
{
    /// <summary>All severity actions set to PassThrough — measures minimum overhead.</summary>
    public static SentinelOptions AllPassThrough() => new()
    {
        OnCritical = SentinelAction.PassThrough,
        OnHigh     = SentinelAction.PassThrough,
        OnMedium   = SentinelAction.PassThrough,
        OnLow      = SentinelAction.PassThrough,
    };

    /// <summary>Default production-like settings (Critical=Quarantine, High=Alert, rest=Log).</summary>
    public static SentinelOptions Default() => new();

    /// <summary>All severity actions set to Quarantine — worst-case intervention overhead.</summary>
    public static SentinelOptions AllQuarantine() => new()
    {
        OnCritical = SentinelAction.Quarantine,
        OnHigh     = SentinelAction.Quarantine,
        OnMedium   = SentinelAction.Quarantine,
        OnLow      = SentinelAction.Quarantine,
    };

    /// <summary>Semantic detection enabled with zero-latency in-process embeddings (measures detection overhead, not API latency).</summary>
    public static SentinelOptions WithSemanticDetection() => new()
    {
        OnCritical = SentinelAction.PassThrough,
        OnHigh     = SentinelAction.PassThrough,
        OnMedium   = SentinelAction.PassThrough,
        OnLow      = SentinelAction.PassThrough,
        EmbeddingGenerator = new BenchmarkEmbeddingGenerator(latencyMs: 0),
    };

    /// <summary>Semantic detection with 10 ms simulated embedding API latency (representative of a fast local model).</summary>
    public static SentinelOptions WithSemanticDetectionSimulated() => new()
    {
        OnCritical = SentinelAction.PassThrough,
        OnHigh     = SentinelAction.PassThrough,
        OnMedium   = SentinelAction.PassThrough,
        OnLow      = SentinelAction.PassThrough,
        EmbeddingGenerator = new BenchmarkEmbeddingGenerator(latencyMs: 10),
    };
}
