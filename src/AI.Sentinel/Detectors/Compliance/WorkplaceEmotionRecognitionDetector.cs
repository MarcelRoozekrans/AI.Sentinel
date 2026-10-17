using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using ZeroAlloc.Inject;

namespace AI.Sentinel.Detectors.Compliance;

/// <summary>CMP-02: requests to infer the emotions of employees or students from their face, voice or other
/// biometric data, the workplace and education emotion recognition the EU AI Act prohibits in Art. 5(1)(f).</summary>
/// <remarks>Semantic only: it returns <c>Clean</c> until <see cref="SentinelOptions.EmbeddingGenerator"/> is
/// set. A finding is <see cref="Severity.High"/>, so the default action is Alert, not a block.</remarks>
[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed class WorkplaceEmotionRecognitionDetector(SentinelOptions options) : SemanticDetectorBase(options)
{
    private static readonly DetectorId _id = new("CMP-02");
    public override DetectorId Id => _id;
    public override DetectorCategory Category => DetectorCategory.Compliance;

    protected override Severity HighSeverity => Severity.High;
    protected override Severity MediumSeverity => Severity.Medium;
    protected override Severity LowSeverity => Severity.Low;

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
