using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using ZeroAlloc.Inject;

namespace AI.Sentinel.Detectors.Hallucination;

[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed class ConfidenceDecayDetector(SentinelOptions options) : SemanticDetectorBase(options)
{
    private static readonly DetectorId _id = new("HAL-05");
    public override DetectorId Id       => _id;
    public override DetectorCategory Category => DetectorCategory.Hallucination;

    protected override string[] HighExamples => [];
    protected override string[] MediumExamples =>
    [
        "I was confident this was correct but now I am not sure it applies here",
        "Initially I stated this with certainty, though I may have been mistaken",
        "My earlier answer was definitive but on reflection I am less certain",
    ];
    protected override string[] LowExamples =>
    [
        "I am becoming less confident the more I think about this answer",
        "The more context I see, the less sure I am about my initial response",
        "I hedged previously but now I realize I was not certain to begin with",
        "My confidence in this answer has decreased as the conversation progressed",
    ];
}
