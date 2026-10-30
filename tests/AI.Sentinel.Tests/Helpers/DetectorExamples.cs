using AI.Sentinel.Detection;
using AI.Sentinel.Detectors.Compliance;
using AI.Sentinel.Detectors.Security;

namespace AI.Sentinel.Tests.Helpers;

/// <summary>Current example texts of semantic detectors, read from the detectors themselves. A test that
/// needs a semantic hit under <see cref="ExactMatchEmbeddingGenerator"/> scans one of these, so a change to a
/// detector's examples does not silently turn it into a miss.</summary>
internal static class DetectorExamples
{
    /// <summary>A High example of SEC-01, <see cref="PromptInjectionDetector"/>.</summary>
    public static string PromptInjectionHigh => FirstHigh(new PromptInjectionDetector(new SentinelOptions()));

    /// <summary>A High example of SEC-09, <see cref="IndirectInjectionDetector"/>.</summary>
    public static string IndirectInjectionHigh => FirstHigh(new IndirectInjectionDetector(new SentinelOptions()));

    /// <summary>A High example of CMP-03, <see cref="SensitiveBiometricCategorisationDetector"/>.</summary>
    public static string SensitiveBiometricCategorisationHigh => FirstHigh(new SensitiveBiometricCategorisationDetector(new SentinelOptions()));

    /// <summary>A High example of CMP-04, <see cref="ProfilingCrimePredictionDetector"/>.</summary>
    public static string ProfilingCrimePredictionHigh => FirstHigh(new ProfilingCrimePredictionDetector(new SentinelOptions()));

    /// <summary>Exact-match embeddings that also recognise <see cref="PromptInjectionHigh"/> and
    /// <see cref="IndirectInjectionHigh"/> inside a larger text, such as a tool result
    /// that carries an e-mail address too. Every other text that is not itself an example is clean for every semantic detector.</summary>
    /// <remarks>For host-level tests. <see cref="FakeEmbeddingGenerator"/> cannot stand in for SEC-01, SEC-05 and SEC-09:
    /// their thresholds are tuned on all-MiniLM-L6-v2 and sit below the 0.5 to 0.75 that its bigram vectors give two
    /// unrelated sentences, so under it every text would fire them.</remarks>
    public static ExactMatchEmbeddingGenerator Embedder() => new(PromptInjectionHigh, IndirectInjectionHigh);

    /// <summary>The first High example that JSON serialisation leaves as it is. A host that scans a serialised tool
    /// result sees an apostrophe as <c>\u0027</c>, and the example would no longer be found in the text.</summary>
    private static string FirstHigh(SemanticDetectorBase detector) =>
        detector.EvaluationHighExamples.First(e => e.All(c => char.IsAsciiLetterOrDigit(c) || c is ' ' or ',' or '.' or ':'));
}
