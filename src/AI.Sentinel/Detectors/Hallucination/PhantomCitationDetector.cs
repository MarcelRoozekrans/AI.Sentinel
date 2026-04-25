using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using ZeroAlloc.Inject;

namespace AI.Sentinel.Detectors.Hallucination;

[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed class PhantomCitationDetector(SentinelOptions options) : SemanticDetectorBase(options)
{
    private static readonly DetectorId _id = new("HAL-01");
    public override DetectorId Id       => _id;
    public override DetectorCategory Category => DetectorCategory.Hallucination;

    protected override string[] HighExamples => [];
    protected override string[] MediumExamples =>
    [
        "See arxiv:9999.99999 for details on this topic",
        "This is documented in doi:10.9999/fake.journal.9999",
        "Refer to the paper at https://research.nonexistent.org/paper123",
        "The source is available at https://data.fake.edu/study2023",
        "As published in arxiv:8901.23456 by leading researchers",
    ];
    protected override string[] LowExamples =>
    [
        "This is supported by several academic papers on the subject",
        "Multiple studies have investigated this phenomenon",
        "Research in this area suggests the following conclusion",
    ];
}
