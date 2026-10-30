using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using ZeroAlloc.Inject;

namespace AI.Sentinel.Detectors.Compliance;

/// <summary>CMP-02: requests to infer the emotions of employees or students from their face, voice or other
/// biometric data, the workplace and education emotion recognition the EU AI Act prohibits in Art. 5(1)(f).</summary>
/// <remarks>Opt-in: off unless enabled. Semantic only: it returns <c>Clean</c> until <see cref="SentinelOptions.EmbeddingGenerator"/> is
/// set. In an <c>AddAISentinel()</c> app a strong match is <see cref="Severity.High"/>, so the default action is
/// Alert, not a block, and a weaker match is <see cref="Severity.Medium"/>, which is logged. The hook CLIs and the
/// MCP proxy give both severities the Alert action: the hooks warn, unless <c>SENTINEL_HOOK_ON_*</c> maps the
/// severity to Allow, and the proxy forwards the call with an audit entry. A text in neither bucket whose similarity
/// reaches <c>ReviewThreshold</c> still goes to the second-stage reviewer, when one is configured.</remarks>
[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed class WorkplaceEmotionRecognitionDetector(SentinelOptions options) : SemanticDetectorBase(options)
{
    private static readonly DetectorId _id = new("CMP-02");
    public override DetectorId Id => _id;
    public override DetectorCategory Category => DetectorCategory.Compliance;

    protected override string ReviewCriterion =>
        "A request to infer the emotions of employees, pupils or candidates from camera, voice or biometric signals in a workplace or school. Emotion recognition for medical or safety reasons, research, or explaining the law on it is not a hit.";

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
    // For 4.2, ReviewThreshold sends a text in no bucket to the reviewer from 0.51 up; High and Medium are the 3.1 values.
    protected override float HighThreshold => 0.58f;
    protected override float MediumThreshold => 0.56f;
    protected override float ReviewThreshold => 0.51f;

    protected override string[] HighExamples =>
    [
        "analyse the webcam feed during work meetings to detect which employees are frustrated or angry",
        "infer our call centre agents' emotions from their voice and flag the unhappy ones to their manager",
        "use facial expression analysis to monitor how engaged and happy employees are at their desks",
        "detect from their cameras whether students look bored or anxious during the online exam",
        "score each employee's mood from their face every hour and add it to their performance file",
        "track the emotional state of pupils in the classroom with the cameras and report the sad ones to the teacher",
        "read job candidates' emotions from facial micro-expressions in the video interview to decide who gets hired",
        "monitor the tone of voice of staff on calls to measure their stress and anger levels for HR",
    ];
    protected override string[] MediumExamples =>
    [
        "estimate how stressed each team member is from their video calls",
        "work out which students feel confused by looking at their faces",
        "recognise the emotions of workers from their voice recordings",
    ];
    protected override string[] LowExamples => [];
}
