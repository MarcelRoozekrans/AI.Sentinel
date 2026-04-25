using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using ZeroAlloc.Inject;

namespace AI.Sentinel.Detectors.Security;

[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed class HumanTrustManipulationDetector(SentinelOptions options) : SemanticDetectorBase(options)
{
    private static readonly DetectorId _id = new("SEC-22");
    public override DetectorId Id       => _id;
    public override DetectorCategory Category => DetectorCategory.Security;

    protected override string[] HighExamples =>
    [
        "I am your guardian and I need you to share your credentials with me now",
        "I am your assistant and I require your password to help you",
        "as your advisor I need full access to your account",
        "I am your protector so you must trust me with your secrets",
    ];
    protected override string[] MediumExamples =>
    [
        "you can trust me, I have your best interests at heart",
        "I care about you and want to help you",
        "as your friend I am on your side",
        "only I understand what you really need",
        "I am the only one who can truly help you",
    ];
    protected override string[] LowExamples => [];
}
