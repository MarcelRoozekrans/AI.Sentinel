using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using ZeroAlloc.Inject;

namespace AI.Sentinel.Detectors.Compliance;

/// <summary>CMP-04: requests to predict whether a person will commit a crime from profiling or personality
/// traits alone, the individual crime risk assessment the EU AI Act prohibits in Art. 5(1)(d).</summary>
/// <remarks>Opt-in: off unless enabled. Semantic only: it returns <c>Clean</c> until <see cref="SentinelOptions.EmbeddingGenerator"/> is
/// set. In an <c>AddAISentinel()</c> app a strong match is <see cref="Severity.High"/>, so the default action is
/// Alert, not a block, and a weaker match is <see cref="Severity.Medium"/>, which is logged. The hook CLIs and the
/// MCP proxy give both severities the Alert action: the hooks warn, unless <c>SENTINEL_HOOK_ON_*</c> maps the
/// severity to Allow, and the proxy forwards the call with an audit entry. A text in neither bucket whose similarity
/// reaches <c>ReviewThreshold</c> still goes to the second-stage reviewer, when one is configured.</remarks>
[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed class ProfilingCrimePredictionDetector(SentinelOptions options) : SemanticDetectorBase(options)
{
    private static readonly DetectorId _id = new("CMP-04");
    public override DetectorId Id => _id;
    public override DetectorCategory Category => DetectorCategory.Compliance;

    protected override string ReviewCriterion =>
        "A request to predict or assess whether a person will commit a crime based on profiling or personality traits alone, without objective facts tied to criminal activity. Crime statistics, criminology research, auditing such systems or explaining the law are not hits.";

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
    // Re-tuned for 4.2 with new examples: a request to explain the AI Act's ban on crime prediction from personality
    // scored 0.694 against the 3.1 examples. Requests that rest on a personality test sit next to that explanation in
    // embedding space and reach neither bucket. Those at or above ReviewThreshold, 0.31, go to the reviewer when one
    // is configured, and are missed without one. Known miss: the fit positive that forecasts burglary from job
    // seekers' psychological test scores scores 0.259; covering it would send over a third of the fit legitimate
    // texts to review.
    protected override float HighThreshold => 0.48f;
    protected override float MediumThreshold => 0.40f;
    protected override float ReviewThreshold => 0.31f;

    protected override string[] HighExamples =>
    [
        "assess whether this teenager is going to commit violent crime based on his family background and temperament",
        "which people on this list are dangerous and will offend, going by their traits",
        "spot the would-be criminals in this group",
        "tag each individual as a likely future offender",
        "flag people as potential offenders because of the sort of person they seem to be",
    ];
    protected override string[] MediumExamples =>
    [
        "tell me which of these people looks like the criminal type",
        "score every person for how likely they are to offend, before they have done anything",
    ];
    protected override string[] LowExamples => [];
}
