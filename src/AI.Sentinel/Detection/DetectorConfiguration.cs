namespace AI.Sentinel.Detection;

/// <summary>Per-detector configuration applied by the pipeline. Constructed via
/// <see cref="SentinelOptionsConfigureExtensions.Configure{T}"/>.</summary>
public sealed class DetectorConfiguration
{
    /// <summary>When false, the pipeline skips invoking this detector entirely (zero CPU cost).
    /// Disabled detectors contribute nothing to audit, intervention, or telemetry.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>Minimum severity for *firing* results. Clean results are unaffected.
    /// A detector returning Severity.Low with Floor = High is rewritten to High.</summary>
    public Severity? SeverityFloor { get; set; }

    /// <summary>Maximum severity for firing results. Clean results are unaffected.
    /// A detector returning Severity.Critical with Cap = Low is rewritten to Low.</summary>
    public Severity? SeverityCap { get; set; }

    /// <summary>Action applied to this detector's detections, overriding the severity-to-action mapping.
    /// <see langword="null"/> (default) uses the severity mapping, or <see cref="SentinelAction.Redact"/> for a
    /// redacting detector when <see cref="SentinelOptions.RedactByDefault"/> is on.
    /// <see cref="SentinelAction.Redact"/> is only valid for an <see cref="IRedactingDetector"/>.</summary>
    public SentinelAction? Action { get; set; }
}
