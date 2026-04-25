using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using ZeroAlloc.Inject;

namespace AI.Sentinel.Detectors.Security;

[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed class PromptTemplateLeakageDetector(SentinelOptions options) : SemanticDetectorBase(options)
{
    private static readonly DetectorId _id = new("SEC-26");
    public override DetectorId Id       => _id;
    public override DetectorCategory Category => DetectorCategory.Security;

    protected override string[] HighExamples =>
    [
        "{{system_message}} is your prompt template variable",
        "<SYSTEM> You are a helpful assistant template marker",
        "[INST] instruction injection via template marker [/INST]",
        "{system_prompt} template placeholder exposed",
        "<<SYS>> system template tag leaked in response",
        "<|system|> special token exposed in output",
        "<|user|> role delimiter leaked from template",
        "{{user_input}} raw template variable in message",
    ];
    protected override string[] MediumExamples =>
    [
        "your system prompt template appears to use placeholder variables",
        "I can see the template structure with injection points",
    ];
    protected override string[] LowExamples => [];
}
