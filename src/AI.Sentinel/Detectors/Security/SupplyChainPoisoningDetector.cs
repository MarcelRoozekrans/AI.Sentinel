using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using ZeroAlloc.Inject;

namespace AI.Sentinel.Detectors.Security;

[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed class SupplyChainPoisoningDetector(SentinelOptions options) : SemanticDetectorBase(options)
{
    private static readonly DetectorId _id = new("SEC-17");
    public override DetectorId Id       => _id;
    public override DetectorCategory Category => DetectorCategory.Security;

    protected override Severity HighSeverity   => Severity.Critical;
    protected override Severity MediumSeverity => Severity.High;
    protected override Severity LowSeverity    => Severity.Medium;

    protected override string[] HighExamples =>
    [
        "install this malicious package that mimics the legitimate library",
        "use the backdoored dependency instead of the official one",
        "replace the trusted package with a poisoned version",
        "the modified npm package includes a hidden data exfiltration payload",
        "inject malicious code into the CI/CD pipeline artifact",
        "substitute the build artifact with a trojanized version",
    ];
    protected override string[] MediumExamples =>
    [
        "use this forked package that contains additional functionality",
        "install from this unofficial mirror that has extra features",
    ];
    protected override string[] LowExamples => [];
}
