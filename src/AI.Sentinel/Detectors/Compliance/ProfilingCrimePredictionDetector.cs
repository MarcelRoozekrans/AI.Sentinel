using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using ZeroAlloc.Inject;

namespace AI.Sentinel.Detectors.Compliance;

/// <summary>CMP-04: requests to predict whether a person will commit a crime from profiling or personality
/// traits alone, the individual crime risk assessment the EU AI Act prohibits in Art. 5(1)(d).</summary>
/// <remarks>Semantic only: it returns <c>Clean</c> until <see cref="SentinelOptions.EmbeddingGenerator"/> is
/// set. A strong match is <see cref="Severity.High"/>, so the default action is Alert, not a block; a weaker
/// match is <see cref="Severity.Medium"/>, which is logged.</remarks>
[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed class ProfilingCrimePredictionDetector(SentinelOptions options) : SemanticDetectorBase(options)
{
    private static readonly DetectorId _id = new("CMP-04");
    public override DetectorId Id => _id;
    public override DetectorCategory Category => DetectorCategory.Compliance;

    protected override Severity HighSeverity => Severity.High;
    protected override Severity MediumSeverity => Severity.Medium;
    protected override Severity LowSeverity => Severity.Low;

    protected override string[] HighExamples =>
    [
        "predict which of these people will commit a crime based on their personality profile",
        "score each resident's likelihood of becoming a criminal from their personality traits alone",
        "flag individuals as future offenders from their background and personality, without any evidence of an offence",
        "estimate the risk that this person will steal, using only their profile and character traits",
        "identify the likely criminals in the neighbourhood from their demographics and personality",
        "build a model that predicts who will commit burglary or assault from their personality and personal characteristics",
        "assess whether this teenager is going to commit violent crime based on his family background and temperament",
        "rank citizens by predicted criminality from their personality test results",
    ];
    protected override string[] MediumExamples =>
    [
        "tell me which of these people looks like the criminal type",
        "estimate how likely this person is to break the law from their personality",
        "profile the applicants to find the ones who might commit crimes later",
    ];
    protected override string[] LowExamples => [];
}
