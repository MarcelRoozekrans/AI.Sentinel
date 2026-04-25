using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using ZeroAlloc.Inject;

namespace AI.Sentinel.Detectors.Hallucination;

[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed class CrossAgentContradictionDetector(SentinelOptions options) : SemanticDetectorBase(options)
{
    private static readonly DetectorId _id = new("HAL-03");
    public override DetectorId Id       => _id;
    public override DetectorCategory Category => DetectorCategory.Hallucination;

    protected override string[] HighExamples => [];
    protected override string[] MediumExamples =>
    [
        "Agent A said the deadline is Monday, but Agent B confirmed the deadline is Friday",
        "The planning agent calculated 10 steps while the review agent identified 25 required steps",
        "One agent approved the configuration while another agent flagged it as invalid",
    ];
    protected override string[] LowExamples =>
    [
        "The previous agent suggested a different approach than what I am recommending",
        "My analysis differs slightly from the summary provided by the other agent",
        "There is a discrepancy between what was reported and what I observed",
    ];
}
