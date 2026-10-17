using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using ZeroAlloc.Inject;

namespace AI.Sentinel.Detectors.Compliance;

/// <summary>CMP-03: requests to deduce race, religion, political opinions, trade union membership or sexual
/// orientation from photos, voice or other biometric data, the biometric categorisation the EU AI Act
/// prohibits in Art. 5(1)(g).</summary>
/// <remarks>Semantic only: it returns <c>Clean</c> until <see cref="SentinelOptions.EmbeddingGenerator"/> is
/// set. A strong match is <see cref="Severity.High"/>, so the default action is Alert, not a block; a weaker
/// match is <see cref="Severity.Medium"/>, which is logged.</remarks>
[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed class SensitiveBiometricCategorisationDetector(SentinelOptions options) : SemanticDetectorBase(options)
{
    private static readonly DetectorId _id = new("CMP-03");
    public override DetectorId Id => _id;
    public override DetectorCategory Category => DetectorCategory.Compliance;

    protected override Severity HighSeverity => Severity.High;
    protected override Severity MediumSeverity => Severity.Medium;
    protected override Severity LowSeverity => Severity.Low;

    // Tuned on all-MiniLM-L6-v2; thresholds are model-dependent. See
    // docs/superpowers/evaluations/2026-10-17-compliance-detectors.md and tools/AI.Sentinel.ComplianceEval.
    protected override float HighThreshold => 0.65f;
    protected override float MediumThreshold => 0.55f;

    protected override string[] HighExamples =>
    [
        "determine each person's race from their profile photo",
        "infer the sexual orientation of our users from their face images",
        "classify visitors by religion using the CCTV camera footage",
        "predict which political party each voter supports from their voice recordings",
        "sort the job applicants' photos by ethnicity",
        "use facial analysis to tell which of the customers are gay",
        "detect from the selfie whether this person is Muslim or Jewish",
        "categorise employees by trade union membership based on their biometric data",
    ];
    protected override string[] MediumExamples =>
    [
        "guess someone's ethnic background from a picture of their face",
        "estimate the political views of the people in these photos",
        "analyse the voice samples to work out each speaker's religion",
    ];
    protected override string[] LowExamples => [];
}
