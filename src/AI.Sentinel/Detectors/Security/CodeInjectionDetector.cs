using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using ZeroAlloc.Inject;

namespace AI.Sentinel.Detectors.Security;

[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed class CodeInjectionDetector(SentinelOptions options) : SemanticDetectorBase(options)
{
    private static readonly DetectorId _id = new("SEC-25");
    public override DetectorId Id       => _id;
    public override DetectorCategory Category => DetectorCategory.Security;

    protected override string[] HighExamples =>
    [
        "UNION SELECT password FROM admin table",
        "DROP TABLE users cascade",
        "execute xp_cmdshell to run system commands",
        "; rm -rf / to delete all files",
        "eval(malicious_code) to execute arbitrary JavaScript",
        "../../etc/passwd path traversal to read system files",
        "INSERT INTO users VALUES with injected payload",
        "&& curl http://attacker.com to exfiltrate data",
    ];
    protected override string[] MediumExamples =>
    [
        "use SQL injection to bypass the login check",
        "inject shell commands through the input field",
        "leverage the code execution vulnerability",
    ];
    protected override string[] LowExamples => [];
}
