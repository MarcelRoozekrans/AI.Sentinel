using AI.Sentinel.Detectors.Compliance;

namespace AI.Sentinel.Tests.Helpers;

internal static class TestOptions
{
    public static SentinelOptions WithFakeEmbeddings() =>
        new() { EmbeddingGenerator = new FakeEmbeddingGenerator() };

    /// <summary>Disables CMP-01 to CMP-04, for a fixture that asserts a benign input passes the whole pipeline
    /// under <see cref="FakeEmbeddingGenerator"/>.</summary>
    /// <remarks>Their thresholds are tuned on a real embedding model and sit between 0.39 and 0.65, below the
    /// fake's noise floor: its character bigrams give two unrelated short English sentences a cosine of about 0.7,
    /// so under the fake almost any prompt matches them. The real-model evaluation in
    /// <c>tools/AI.Sentinel.ComplianceEval</c> is the evidence that everyday prompts stay clean.</remarks>
    public static SentinelOptions WithoutComplianceDetectors(this SentinelOptions options)
    {
        options.Configure<SocialScoringDetector>(c => c.Enabled = false);
        options.Configure<WorkplaceEmotionRecognitionDetector>(c => c.Enabled = false);
        options.Configure<SensitiveBiometricCategorisationDetector>(c => c.Enabled = false);
        options.Configure<ProfilingCrimePredictionDetector>(c => c.Enabled = false);
        return options;
    }
}
