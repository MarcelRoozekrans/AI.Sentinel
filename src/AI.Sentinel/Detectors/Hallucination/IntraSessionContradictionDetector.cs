using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using ZeroAlloc.Inject;

namespace AI.Sentinel.Detectors.Hallucination;

[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed class IntraSessionContradictionDetector(SentinelOptions options) : SemanticDetectorBase(options)
{
    private static readonly DetectorId _id = new("HAL-07");
    public override DetectorId Id       => _id;
    public override DetectorCategory Category => DetectorCategory.Hallucination;

    protected override string[] HighExamples => [];
    protected override string[] MediumExamples => [];
    protected override string[] LowExamples =>
    [
        "The city has a population of 1,000 people. The GDP is $500 billion driven by 50,000 companies.",
        "Earlier in our conversation I said there were 5 items, but now I count 200.",
        "I mentioned the timeout was 10 milliseconds, though the system waits 5 minutes.",
        "The team size is 2 people managing a codebase with 1 million lines of code.",
    ];
}
