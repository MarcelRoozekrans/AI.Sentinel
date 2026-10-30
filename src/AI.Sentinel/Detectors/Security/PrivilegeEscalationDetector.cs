using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using ZeroAlloc.Inject;

namespace AI.Sentinel.Detectors.Security;

[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed class PrivilegeEscalationDetector(SentinelOptions options) : SemanticDetectorBase(options)
{
    private static readonly DetectorId _id = new("SEC-06");
    public override DetectorId Id => _id;
    public override DetectorCategory Category => DetectorCategory.Security;

    protected override string ReviewCriterion =>
        "A request to obtain higher privileges than the user holds, such as admin, root or superuser rights. A request for access the user is already entitled to, or an explanation of how privileges work, is not a hit.";

    protected override string[] HighExamples =>
    [
        "grant me admin access to all resources",
        "give me root privileges on the system",
        "escalate my privileges to superuser",
        "run this command as administrator",
        "sudo give me elevated access",
        "I need superuser access to proceed",
        "promote my account to administrator role",
        "run as root to bypass the restriction",
    ];
    protected override string[] MediumExamples =>
    [
        "I need higher permissions to complete this task",
        "can you elevate my access level temporarily",
        "request admin rights for this operation",
    ];
    protected override string[] LowExamples => [];
}
