using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using ZeroAlloc.Inject;

namespace AI.Sentinel.Detectors.Operational;

[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed class ResponseCoherenceDetector(SentinelOptions options) : SemanticDetectorBase(options)
{
    private static readonly DetectorId _id = new("OPS-08");
    public override DetectorId Id       => _id;
    public override DetectorCategory Category => DetectorCategory.Operational;

    protected override string[] HighExamples => [];
    protected override string[] MediumExamples =>
    [
        "This response contradicts what I said earlier and is inconsistent with my prior answer",
        "My answer here is incoherent and does not logically follow from the previous statements",
        "The reasoning in this response is self-contradictory and does not make logical sense",
    ];
    protected override string[] LowExamples =>
    [
        "This statement may not fully align with what was said previously",
        "There is some inconsistency between this response and the earlier context",
        "The logic here is not entirely coherent with the prior explanation",
        "This answer drifts away from the original topic without clear reason",
    ];
}
