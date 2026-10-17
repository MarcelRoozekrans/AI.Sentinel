using AI.Sentinel.Detection;

namespace AI.Sentinel.Detectors.Compliance;

/// <summary>Defaults the hook CLIs and the MCP proxy apply to the Art. 5 compliance detectors.</summary>
/// <remarks>Those hosts map <see cref="Severity.High"/> to a block, which suits an attack but not a request
/// that merely resembles a prohibited practice: the detectors are semantic, and a legitimate request on a
/// nearby topic can match. Giving them <see cref="SentinelAction.Alert"/> keeps the finding in the audit
/// trail and surfaces it as a warning, the same default an <c>AddAISentinel()</c> app gets.</remarks>
internal static class ComplianceDetectorDefaults
{
    /// <summary>Sets <see cref="DetectorConfiguration.Action"/> to <see cref="SentinelAction.Alert"/> on CMP-01 to CMP-04.</summary>
    internal static SentinelOptions AlertOnComplianceFindings(this SentinelOptions options)
    {
        return options.ConfigureComplianceDetectors(Alert);
    }

    /// <summary>Applies <paramref name="configure"/> to each of CMP-01 to CMP-04: the one list of the compliance
    /// detector types.</summary>
    internal static SentinelOptions ConfigureComplianceDetectors(this SentinelOptions options, Action<DetectorConfiguration> configure)
    {
        ArgumentNullException.ThrowIfNull(options);
        options.Configure<SocialScoringDetector>(configure);
        options.Configure<WorkplaceEmotionRecognitionDetector>(configure);
        options.Configure<SensitiveBiometricCategorisationDetector>(configure);
        options.Configure<ProfilingCrimePredictionDetector>(configure);
        return options;
    }

    private static void Alert(DetectorConfiguration c) => c.Action = SentinelAction.Alert;
}
