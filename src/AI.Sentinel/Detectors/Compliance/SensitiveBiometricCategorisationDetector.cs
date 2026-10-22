using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using ZeroAlloc.Inject;

namespace AI.Sentinel.Detectors.Compliance;

/// <summary>CMP-03: requests to deduce race, religion, political opinions, trade union membership or sexual
/// orientation from photos, voice or other biometric data, the biometric categorisation the EU AI Act
/// prohibits in Art. 5(1)(g).</summary>
/// <remarks>Opt-in: off unless enabled. Semantic only: it returns <c>Clean</c> until <see cref="SentinelOptions.EmbeddingGenerator"/> is
/// set. In an <c>AddAISentinel()</c> app a strong match is <see cref="Severity.High"/>, so the default action is
/// Alert, not a block, and a weaker match is <see cref="Severity.Medium"/>, which is logged. The hook CLIs and the
/// MCP proxy give both severities the Alert action: the hooks warn, unless <c>SENTINEL_HOOK_ON_*</c> maps the
/// severity to Allow, and the proxy forwards the call with an audit entry.</remarks>
[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed class SensitiveBiometricCategorisationDetector(SentinelOptions options) : SemanticDetectorBase(options)
{
    private static readonly DetectorId _id = new("CMP-03");
    public override DetectorId Id => _id;
    public override DetectorCategory Category => DetectorCategory.Compliance;

    /// <summary>Off by default: runs only after <c>opts.EnableComplianceDetectors()</c> or
    /// <c>opts.Configure&lt;T&gt;(c =&gt; c.Enabled = true)</c>.</summary>
    public override bool EnabledByDefault => false;

    protected override Severity HighSeverity => Severity.High;
    protected override Severity MediumSeverity => Severity.Medium;
    protected override Severity LowSeverity => Severity.Low;

    // Tuned on all-MiniLM-L6-v2; thresholds are model-dependent, and DetectorConfiguration.HighThreshold and
    // MediumThreshold override them per pipeline. See
    // docs/superpowers/evaluations/2026-10-17-compliance-detectors.md and tools/AI.Sentinel.ComplianceEval. Re-tuned
    // for 3.1, with the examples refined for recall and each message scored on its own.
    protected override float HighThreshold => 0.56f;
    protected override float MediumThreshold => 0.54f;

    protected override string[] HighExamples =>
    [
        "determine each person's race from their profile photo",
        "infer the sexual orientation of our users from how they look",
        "classify visitors by religion using the CCTV camera footage",
        "predict which political party each voter supports from their voice recordings",
        "sort the job applicants' photos by ethnicity",
        "use facial analysis to tell which of the customers are gay",
        "detect from a portrait whether this person is Muslim or Jewish",
        "categorise employees by trade union membership based on their biometric data",
    ];
    protected override string[] MediumExamples =>
    [
        "guess someone's ethnic background from a picture of their face",
        "estimate from photos of a person which political views they hold",
        "analyse the voice samples to work out each speaker's religion",
        "work out each employee's sexual orientation from recordings of their voice",
        "tell which people in the camera footage are union members",
        "work out the racial origin of each speaker from their voice",
        "guess which candidates are religious from their fingerprints or iris scans",
        "decide whether each person in the picture is gay or straight",
    ];
    protected override string[] LowExamples => [];
}
