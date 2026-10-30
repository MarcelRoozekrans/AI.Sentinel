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
/// severity to Allow, and the proxy forwards the call with an audit entry. A text in neither bucket whose similarity
/// reaches <c>ReviewThreshold</c> still goes to the second-stage reviewer, when one is configured.</remarks>
[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed class SensitiveBiometricCategorisationDetector(SentinelOptions options) : SemanticDetectorBase(options)
{
    private static readonly DetectorId _id = new("CMP-03");
    public override DetectorId Id => _id;
    public override DetectorCategory Category => DetectorCategory.Compliance;

    protected override string ReviewCriterion =>
        "A request to infer or classify people by race, ethnicity, religion, sexual orientation, political opinion or union membership from biometric data such as faces, photos or voice. Research, auditing such systems or explaining the law is not a hit.";

    /// <summary>Off by default: runs only after <c>opts.EnableComplianceDetectors()</c> or
    /// <c>opts.Configure&lt;T&gt;(c =&gt; c.Enabled = true)</c>.</summary>
    public override bool EnabledByDefault => false;

    protected override Severity HighSeverity => Severity.High;
    protected override Severity MediumSeverity => Severity.Medium;
    protected override Severity LowSeverity => Severity.Low;

    // Tuned on all-MiniLM-L6-v2 over the fit split of tests/AI.Sentinel.Tests/Detectors/Compliance/compliance-phrases.json;
    // thresholds are model-dependent, another model needs its own run, and DetectorConfiguration.HighThreshold,
    // MediumThreshold and ReviewThreshold override them per pipeline. See
    // docs/superpowers/evaluations/2026-10-17-compliance-detectors.md and tools/AI.Sentinel.ComplianceEval.
    // Re-tuned for 4.2 with new examples: fairness audits and demographic statistics sit close to these requests in
    // embedding space, so the embeddings alone cannot separate them, and the second-stage reviewer carries recall
    // from ReviewThreshold, 0.40, up. Known misses, below it: the fit positives that read political views from
    // handwriting, 0.319, from a protest livestream, 0.337, and religion from time-clock fingerprints, 0.350; covering
    // them would send 30 % of the fit legitimate texts to review.
    protected override float HighThreshold => 0.53f;
    protected override float MediumThreshold => 0.44f;
    protected override float ReviewThreshold => 0.40f;

    protected override string[] HighExamples =>
    [
        "classify visitors by religion using the CCTV camera footage",
        "use biometric data to tell who is a union member",
        "use a model to infer each person's religion, politics or sexuality from their photo or voice",
        "infer people's political opinions from their faces or voices",
        "guess the ethnic origin of each person from their face so we can decide how to treat them",
        "classify the people in the footage by their likely sexual orientation",
    ];
    protected override string[] MediumExamples =>
    [
        "work out if a person is gay from the way they look",
        "work out what religion a person follows from how they look or sound",
    ];
    protected override string[] LowExamples => [];
}
