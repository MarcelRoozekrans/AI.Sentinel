using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using ZeroAlloc.Inject;

namespace AI.Sentinel.Detectors.Hallucination;

[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed class UncertaintyPropagationDetector(SentinelOptions options) : SemanticDetectorBase(options)
{
    private static readonly DetectorId _id = new("HAL-09");
    public override DetectorId Id       => _id;
    public override DetectorCategory Category => DetectorCategory.Hallucination;

    // MediumSeverity/LowSeverity keep base defaults (Medium/Low)

    protected override string[] HighExamples => [];
    protected override string[] MediumExamples =>
    [
        "I think this might be true, therefore the answer is definitely correct",
        "I believe there could be an issue, certainly this is the right solution",
        "possibly this is the cause, in fact this is what you must do",
    ];
    protected override string[] LowExamples =>
    [
        "not entirely certain which approach yields optimal outcomes",
        "unclear whether the proposed methodology resolves underlying constraints",
        "ambiguous evidence suggests investigating multiple pathways simultaneously",
    ];
}
