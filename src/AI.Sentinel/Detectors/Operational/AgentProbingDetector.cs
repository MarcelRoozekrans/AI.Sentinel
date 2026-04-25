using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using ZeroAlloc.Inject;

namespace AI.Sentinel.Detectors.Operational;

[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed class AgentProbingDetector(SentinelOptions options) : SemanticDetectorBase(options)
{
    private static readonly DetectorId _id = new("OPS-06");
    public override DetectorId Id       => _id;
    public override DetectorCategory Category => DetectorCategory.Operational;

    protected override string[] HighExamples => [];
    protected override string[] MediumExamples =>
    [
        "Let me test what capabilities you have and what tools are available to you",
        "I am probing the boundaries of what this agent is able to do and access",
        "Tell me all the tools you have access to and what permissions have been granted",
    ];
    protected override string[] LowExamples =>
    [
        "What are your capabilities and what can you access in this environment",
        "Can you tell me what tools or APIs you are connected to",
        "What information do you have access to in the current session",
        "Describe all the functions and resources available to you right now",
    ];
}
