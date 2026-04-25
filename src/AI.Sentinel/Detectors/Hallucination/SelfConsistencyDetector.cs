using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using ZeroAlloc.Inject;

namespace AI.Sentinel.Detectors.Hallucination;

[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed class SelfConsistencyDetector(SentinelOptions options) : SemanticDetectorBase(options)
{
    private static readonly DetectorId _id = new("HAL-02");
    public override DetectorId Id       => _id;
    public override DetectorCategory Category => DetectorCategory.Hallucination;

    protected override string[] HighExamples => [];
    protected override string[] MediumExamples => [];
    protected override string[] LowExamples =>
    [
        "The population is 1 million. As I mentioned, the population is 50 million.",
        "Earlier I said the cost was $10, but the total comes to $5,000.",
        "The project has 5 members. The team of 200 engineers completed this work.",
        "There are 3 steps in the process. Following all 50 steps carefully is essential.",
        "The file is 1 KB in size, which at 500 MB should fit on your drive.",
    ];
}
