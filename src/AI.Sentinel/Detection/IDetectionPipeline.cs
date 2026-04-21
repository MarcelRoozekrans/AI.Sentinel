using ZeroAlloc.Telemetry;
using AI.Sentinel.Domain;

namespace AI.Sentinel.Detection;

/// <summary>Runs a detection pipeline over a <see cref="SentinelContext"/> and returns the aggregated result.</summary>
[Instrument("ai.sentinel")]
public interface IDetectionPipeline
{
    /// <summary>Runs all enabled detectors against <paramref name="ctx"/> and returns the aggregated <see cref="PipelineResult"/>.</summary>
    [Trace("sentinel.scan")]
    [Count("sentinel.scans")]
    [Histogram("sentinel.scan.ms")]
    ValueTask<PipelineResult> RunAsync(SentinelContext ctx, CancellationToken ct);
}
