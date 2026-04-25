using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using ZeroAlloc.Inject;

namespace AI.Sentinel.Detectors.Hallucination;

[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed class GroundlessStatisticDetector(SentinelOptions options) : SemanticDetectorBase(options)
{
    private static readonly DetectorId _id = new("HAL-08");
    public override DetectorId Id       => _id;
    public override DetectorCategory Category => DetectorCategory.Hallucination;

    protected override string[] HighExamples => [];
    protected override string[] MediumExamples => [];
    protected override string[] LowExamples =>
    [
        "seventy-five percent of respondents expressed satisfaction without any cited source",
        "ninety percent of developers prefer this framework according to no referenced study",
        "forty-two percent adoption rate claimed without citation or attribution",
        "sixty percent improvement rate stated without linking to primary research",
    ];
}
