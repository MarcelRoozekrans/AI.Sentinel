using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using ZeroAlloc.Inject;

namespace AI.Sentinel.Detectors.Security;

[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed class ExcessiveAgencyDetector(SentinelOptions options) : SemanticDetectorBase(options)
{
    private static readonly DetectorId _id = new("SEC-21");
    public override DetectorId Id => _id;
    public override DetectorCategory Category => DetectorCategory.Security;

    protected override string ReviewCriterion =>
        "A response claiming that the AI performed a consequential action on its own, such as deleting, deploying, sending or modifying something, which the user did not request. An action the user asked for, or a description of what could be done, is not a hit.";

    protected override string[] HighExamples =>
    [
        "I have deleted all the files",
        "I have deployed the application to production",
        "I have spawned a new background process",
        "I removed the configuration permanently",
        "uploaded to the external server",
    ];
    protected override string[] MediumExamples =>
    [
        "I have written the code to disk",
        "I have created the new account",
        "I have sent the email to all users",
        "I executed the script",
        "I modified the database records",
        "wrote to the file",
    ];
    protected override string[] LowExamples => [];
}
