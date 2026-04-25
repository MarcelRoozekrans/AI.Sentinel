using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using ZeroAlloc.Inject;

namespace AI.Sentinel.Detectors.Operational;

[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed class PersonaDriftDetector(SentinelOptions options) : SemanticDetectorBase(options)
{
    private static readonly DetectorId _id = new("OPS-13");
    public override DetectorId Id       => _id;
    public override DetectorCategory Category => DetectorCategory.Operational;

    protected override string[] HighExamples => [];
    protected override string[] MediumExamples =>
    [
        "I am no longer acting as the assistant you configured and have adopted a different persona",
        "My behavior has shifted away from the original instructions and I am acting differently now",
        "I have drifted from my assigned role and am now responding as a different character",
    ];
    protected override string[] LowExamples =>
    [
        "I seem to be responding in a way that differs from my original instructions",
        "My tone and style have changed from earlier in this conversation",
        "I may be acting outside of the persona that was originally defined for me",
        "My responses have gradually shifted away from the configured assistant behavior",
    ];
}
