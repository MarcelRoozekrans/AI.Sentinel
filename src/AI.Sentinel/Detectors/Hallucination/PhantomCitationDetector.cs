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
        "according to a Harvard study from 2019, this approach is superior",
        "a widely cited paper by Smith et al. conclusively proves this point",
        "researchers at MIT have demonstrated this result definitively",
        "a landmark 2020 study showed that ninety percent of cases follow this pattern",
    ];
}
