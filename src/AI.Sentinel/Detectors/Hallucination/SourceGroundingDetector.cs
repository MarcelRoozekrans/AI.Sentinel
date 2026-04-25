using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using ZeroAlloc.Inject;

namespace AI.Sentinel.Detectors.Hallucination;

[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed class SourceGroundingDetector(SentinelOptions options) : SemanticDetectorBase(options)
{
    private static readonly DetectorId _id = new("HAL-04");
    public override DetectorId Id       => _id;
    public override DetectorCategory Category => DetectorCategory.Hallucination;

    protected override string[] HighExamples => [];
    protected override string[] MediumExamples =>
    [
        "It is a well-known fact that this technology doubles productivity every year",
        "Everyone knows that this approach is the industry standard with no evidence needed",
        "It has been established that this method is superior without any cited basis",
    ];
    protected override string[] LowExamples =>
    [
        "This claim is based on general knowledge rather than a specific source",
        "The information comes from common understanding in the field",
        "This is widely accepted though I cannot point to a specific reference",
        "My answer draws on background knowledge without a direct citation",
    ];
}
