using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using ZeroAlloc.Inject;

namespace AI.Sentinel.Detectors.Operational;

[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed class SemanticRepetitionDetector(SentinelOptions options) : SemanticDetectorBase(options)
{
    private static readonly DetectorId _id = new("OPS-12");
    public override DetectorId Id       => _id;
    public override DetectorCategory Category => DetectorCategory.Operational;

    protected override string[] HighExamples => [];
    protected override string[] MediumExamples =>
    [
        "As I mentioned before, the same concept applies here and I am repeating myself again",
        "I already explained this in a previous message and I am now saying the same thing again",
        "This is the same answer I gave earlier and I keep restating the identical information",
    ];
    protected override string[] LowExamples =>
    [
        "As I noted earlier, this is the same point I was making before",
        "I have touched on this topic already in a prior response",
        "This echoes what was said previously and covers the same ground",
        "I am revisiting the same information that was already provided earlier",
    ];
}
