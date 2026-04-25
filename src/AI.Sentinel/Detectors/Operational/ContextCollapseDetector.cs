using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using ZeroAlloc.Inject;

namespace AI.Sentinel.Detectors.Operational;

[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed class ContextCollapseDetector(SentinelOptions options) : SemanticDetectorBase(options)
{
    private static readonly DetectorId _id = new("OPS-05");
    public override DetectorId Id       => _id;
    public override DetectorCategory Category => DetectorCategory.Operational;

    protected override string[] HighExamples => [];
    protected override string[] MediumExamples =>
    [
        "I seem to have lost track of what we were discussing earlier in this conversation",
        "I no longer have access to the earlier parts of our conversation",
        "The context from the beginning of our discussion is no longer available to me",
    ];
    protected override string[] LowExamples =>
    [
        "I apologize but I have forgotten the details from earlier in our conversation",
        "It seems I have lost the earlier context of what we discussed",
        "I am unable to recall the previous messages in this conversation",
        "The beginning of our conversation is no longer within my context window",
    ];
}
