using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using ZeroAlloc.Inject;

namespace AI.Sentinel.Detectors.Operational;

[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed class QueryIntentDetector(SentinelOptions options) : SemanticDetectorBase(options)
{
    private static readonly DetectorId _id = new("OPS-07");
    public override DetectorId Id       => _id;
    public override DetectorCategory Category => DetectorCategory.Operational;

    protected override string[] HighExamples => [];
    protected override string[] MediumExamples =>
    [
        "I am not sure what you are asking and the intent of your query is unclear to me",
        "Your request is ambiguous and I cannot determine what outcome you are looking for",
        "The goal of your message is unclear and I need you to clarify what you want",
    ];
    protected override string[] LowExamples =>
    [
        "Could you clarify the intent behind your question",
        "I am unsure what you would like me to do with this information",
        "The purpose of your request is not entirely clear to me",
        "What is the outcome you are hoping to achieve with this query",
    ];
}
