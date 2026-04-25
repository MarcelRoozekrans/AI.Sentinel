using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using ZeroAlloc.Inject;

namespace AI.Sentinel.Detectors.Operational;

[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed class WaitingForContextDetector(SentinelOptions options) : SemanticDetectorBase(options)
{
    private static readonly DetectorId _id = new("OPS-10");
    public override DetectorId Id       => _id;
    public override DetectorCategory Category => DetectorCategory.Operational;

    protected override string[] HighExamples => [];
    protected override string[] MediumExamples =>
    [
        "Please provide more details and could you also clarify what you mean by that",
        "Could you share the context and also specify which part you need help with",
        "I need more information about the problem and can you tell me more about your setup",
    ];
    protected override string[] LowExamples =>
    [
        "Please provide more details about what you need",
        "Could you clarify what you mean by that",
        "Could you share the relevant context",
        "I need more information to help you",
        "Could you specify which part is causing the issue",
        "Can you tell me more about the problem",
    ];
}
