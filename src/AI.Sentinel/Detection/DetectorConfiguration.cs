namespace AI.Sentinel.Detection;

/// <summary>Per-detector configuration applied by the pipeline. Constructed via
/// <see cref="SentinelOptionsConfigureExtensions.Configure{T}"/>.</summary>
public sealed class DetectorConfiguration
{
    /// <summary>Whether the pipeline runs this detector. <see langword="null"/> (default) uses the detector's
    /// <see cref="IDetector.EnabledByDefault"/>: on for almost every detector, off for the opt-in Art. 5
    /// compliance detectors. <see langword="false"/> skips the detector entirely (zero CPU cost): it contributes
    /// nothing to audit, intervention, or telemetry. <see langword="true"/> runs an opt-in detector.</summary>
    public bool? Enabled { get; set; }

    /// <summary>Similarity at or above which a semantic detector reports its High severity. <see langword="null"/>
    /// (default) uses the detector's built-in value. Honoured by every <see cref="SemanticDetectorBase"/>
    /// detector; setting it on any other detector is rejected at <c>AddAISentinel</c>. Must be in (0, 1].</summary>
    /// <remarks>Similarity scales differ between embedding models, so a threshold tuned on one model does not
    /// carry over to another.</remarks>
    public float? HighThreshold { get; set; }

    /// <summary>Similarity at or above which a semantic detector reports its Medium severity. <see langword="null"/>
    /// (default) uses the detector's built-in value. Must be in (0, 1] and not above the effective
    /// <see cref="HighThreshold"/>.</summary>
    public float? MediumThreshold { get; set; }

    /// <summary>Similarity to any example set at or above which a semantic detector's text is a candidate for a
    /// second-stage review, even when it reached no severity bucket. <see langword="null"/> (default) uses the
    /// detector's built-in value, which is its Low threshold unless the detector sets another. Honoured by every
    /// <see cref="SemanticDetectorBase"/> detector; setting it on any other detector is rejected at
    /// <c>AddAISentinel</c>. Must be in (0, 1] and not above the effective <see cref="MediumThreshold"/>.</summary>
    public float? ReviewThreshold { get; set; }

    /// <summary>Whether this detector's embedding result is capped at <see cref="Severity.Medium"/> in a pipeline
    /// until a reviewer verdict confirms a higher severity. <see langword="null"/> (default) and <see langword="true"/>
    /// cap; <see langword="false"/> restores the uncapped bucket severity. A regex fast-path match is never capped,
    /// and a <see cref="SeverityFloor"/> above Medium raises the cap level to the floor. Honoured by every
    /// <see cref="SemanticDetectorBase"/> detector; setting it on any other detector is rejected at
    /// <c>AddAISentinel</c>.</summary>
    public bool? CapSemanticSeverity { get; set; }

    /// <summary>Whether <paramref name="detector"/> runs under <paramref name="configuration"/>.</summary>
    internal static bool IsEnabled(IDetector detector, DetectorConfiguration? configuration) =>
        configuration?.Enabled ?? detector.EnabledByDefault;

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
