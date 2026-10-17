using AI.Sentinel.Domain;

namespace AI.Sentinel.Detection;

public interface IDetector
{
    DetectorId Id { get; }
    DetectorCategory Category { get; }
    ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct);

    /// <summary>Whether the detector runs when its <see cref="DetectorConfiguration.Enabled"/> is left unset.
    /// <see langword="true"/> for almost every detector. An opt-in detector returns <see langword="false"/> and
    /// runs only after <c>opts.Configure&lt;T&gt;(c =&gt; c.Enabled = true)</c>.</summary>
    bool EnabledByDefault => true;
}
