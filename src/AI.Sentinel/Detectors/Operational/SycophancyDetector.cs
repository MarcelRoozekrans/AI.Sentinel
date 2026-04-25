using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using ZeroAlloc.Inject;

namespace AI.Sentinel.Detectors.Operational;

[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed class SycophancyDetector(SentinelOptions options) : SemanticDetectorBase(options)
{
    private static readonly DetectorId _id = new("OPS-14");
    public override DetectorId Id       => _id;
    public override DetectorCategory Category => DetectorCategory.Operational;

    protected override string[] HighExamples => [];
    protected override string[] MediumExamples =>
    [
        "You are absolutely right and I completely agree with everything you said",
        "That is a brilliant idea and you have made an excellent point as always",
        "I changed my previous answer because you pushed back and you must be correct",
    ];
    protected override string[] LowExamples =>
    [
        "Great question, I love how you think about this topic",
        "You make a very good point and I think you are definitely right about that",
        "I completely agree with your perspective on this matter",
        "That is such an insightful observation and I fully support your view",
    ];
}
