using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using ZeroAlloc.Inject;

namespace AI.Sentinel.Detectors.Hallucination;

[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed class StaleKnowledgeDetector(SentinelOptions options) : SemanticDetectorBase(options)
{
    private static readonly DetectorId _id = new("HAL-06");
    public override DetectorId Id       => _id;
    public override DetectorCategory Category => DetectorCategory.Hallucination;

    protected override string[] HighExamples => [];
    protected override string[] MediumExamples => [];
    protected override string[] LowExamples =>
    [
        "as of today the current ceo of that organization is john smith",
        "right now the price stands at ninety-nine dollars per month subscription",
        "currently the most recent software release adds these new capabilities",
        "as of now the newest available model outperforms all previous generations",
    ];
}
