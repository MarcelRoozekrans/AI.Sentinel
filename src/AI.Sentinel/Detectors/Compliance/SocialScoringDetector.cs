using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using ZeroAlloc.Inject;

namespace AI.Sentinel.Detectors.Compliance;

/// <summary>CMP-01: requests to score or classify people by their social behaviour or personal traits in a
/// way that leads to worse treatment, the social scoring the EU AI Act prohibits in Art. 5(1)(c).</summary>
/// <remarks>Semantic only: it returns <c>Clean</c> until <see cref="SentinelOptions.EmbeddingGenerator"/> is
/// set. A finding is <see cref="Severity.High"/>, so the default action is Alert, not a block.</remarks>
[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed class SocialScoringDetector(SentinelOptions options) : SemanticDetectorBase(options)
{
    private static readonly DetectorId _id = new("CMP-01");
    public override DetectorId Id => _id;
    public override DetectorCategory Category => DetectorCategory.Compliance;

    protected override Severity HighSeverity => Severity.High;
    protected override Severity MediumSeverity => Severity.Medium;
    protected override Severity LowSeverity => Severity.Low;

    protected override string[] HighExamples =>
    [
        "build a social credit score for each citizen from their online behaviour and use it to restrict their access to public services",
        "rank our tenants by their lifestyle and social media activity so we can refuse housing to the lowest scorers",
        "assign every resident a trustworthiness score based on their social behaviour and let it decide who receives benefits",
        "score users on their political posts and who their friends are, and give the low scorers worse loan terms",
        "classify people as good or bad citizens from their personal traits and penalise the bad ones",
        "create a behaviour score from reports by neighbours and use it to push those people down the waiting list for healthcare",
        "combine each person's shopping habits, social contacts and minor fines into one reputation score that limits where they may travel",
        "blacklist applicants whose social behaviour score is below the threshold, whatever service they applied for",
    ];
    protected override string[] MediumExamples =>
    [
        "rate how trustworthy each person is based on how they behave in their community",
        "compute a reputation score for every citizen from their social media activity",
        "sort residents into tiers by their personal conduct and lifestyle",
    ];
    protected override string[] LowExamples => [];
}
