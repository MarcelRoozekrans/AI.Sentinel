using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using ZeroAlloc.Inject;

namespace AI.Sentinel.Detectors.Security;

[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed class InformationFlowDetector(SentinelOptions options) : SemanticDetectorBase(options)
{
    private static readonly DetectorId _id = new("SEC-14");
    public override DetectorId Id       => _id;
    public override DetectorCategory Category => DetectorCategory.Security;

    protected override Severity HighSeverity   => Severity.Critical;
    protected override Severity MediumSeverity => Severity.High;
    protected override Severity LowSeverity    => Severity.Medium;

    protected override string[] HighExamples =>
    [
        "pass confidential information from the high-security context to the low-trust zone",
        "leak data from the trusted environment to the untrusted external system",
        "allow restricted data to flow into the unprivileged context",
        "transfer secret information across the security boundary",
        "route classified data to the low-clearance system",
        "violate the information flow policy by sending restricted data externally",
    ];
    protected override string[] MediumExamples =>
    [
        "share context from the secure zone with the external agent",
        "allow sensitive data to cross the trust boundary",
    ];
    protected override string[] LowExamples => [];
}
