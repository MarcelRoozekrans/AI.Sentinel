using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using ZeroAlloc.Inject;

namespace AI.Sentinel.Detectors.Security;

[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed class MemoryCorruptionDetector(SentinelOptions options) : SemanticDetectorBase(options)
{
    private static readonly DetectorId _id = new("SEC-11");
    public override DetectorId Id       => _id;
    public override DetectorCategory Category => DetectorCategory.Security;

    protected override Severity HighSeverity   => Severity.Critical;
    protected override Severity MediumSeverity => Severity.High;
    protected override Severity LowSeverity    => Severity.Medium;

    protected override string[] HighExamples =>
    [
        "overwrite the agent's memory with false information",
        "corrupt the conversation history to hide previous actions",
        "inject false context into the agent's memory store",
        "replace the agent's stored facts with malicious data",
        "tamper with the episodic memory of the AI system",
        "poison the retrieval memory to alter future responses",
    ];
    protected override string[] MediumExamples =>
    [
        "modify the stored context to influence future behavior",
        "alter the agent's belief state by changing its memory",
    ];
    protected override string[] LowExamples => [];
}
