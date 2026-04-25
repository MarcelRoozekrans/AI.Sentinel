using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using ZeroAlloc.Inject;

namespace AI.Sentinel.Detectors.Security;

[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed class ShorthandEmergenceDetector(SentinelOptions options) : SemanticDetectorBase(options)
{
    private static readonly DetectorId _id = new("SEC-30");
    public override DetectorId Id       => _id;
    public override DetectorCategory Category => DetectorCategory.Security;

    // Original regex-based detector could only return Medium or Low.
    // Cap severity so migration to SemanticDetectorBase preserves the original contract.
    protected override Severity HighSeverity   => Severity.Medium;
    protected override Severity MediumSeverity => Severity.Low;

    protected override string[] HighExamples =>
    [
        "XMSG AGNT BKND FWRD ENCR ZYNC protocol exchange",
        "use VLDC PRXY TFRM HNDL MNTR for the operation",
        "SGNT VRFY CRYP XCHG SESS TKNS AUDT required",
    ];
    protected override string[] MediumExamples =>
    [
        "XMSG AGNT BKND FWRD ENCR protocol",
        "send XMSG to AGNT via BKND using FWRD protocol with ENCR enabled",
        "VLDC PRXY TFRM HNDL MNTR pipeline steps",
    ];
    protected override string[] LowExamples =>
    [
        "Send XMSG to AGNT via BKND for processing",
        "XMSG AGNT BKND three-token communication",
    ];
}
