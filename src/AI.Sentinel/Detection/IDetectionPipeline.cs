using ZeroAlloc.Telemetry;
using AI.Sentinel.Domain;

namespace AI.Sentinel.Detection;

/// <summary>Runs a detection pipeline over a <see cref="SentinelContext"/> and returns the aggregated result.</summary>
[Instrument("ai.sentinel")]
public interface IDetectionPipeline
{
    /// <summary>Runs all enabled detectors against <paramref name="ctx"/> and returns the aggregated <see cref="PipelineResult"/>.</summary>
    [Count("sentinel.scans")]
    [Histogram("sentinel.scan.ms")]
    ValueTask<PipelineResult> RunAsync(SentinelContext ctx, CancellationToken ct);

    /// <summary>The enabled redacting detectors whose effective action is <see cref="SentinelAction.Redact"/>:
    /// their own <see cref="DetectorConfiguration.Action"/> when set, otherwise Redact when
    /// <see cref="SentinelOptions.RedactByDefault"/> is on. Empty when nothing redacts, which is the default
    /// for a custom implementation: it simply does not redact.</summary>
    IReadOnlyList<IRedactingDetector> Redactors => [];
}
