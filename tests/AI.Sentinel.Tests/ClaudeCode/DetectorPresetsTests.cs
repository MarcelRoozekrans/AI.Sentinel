using Xunit;
using AI.Sentinel.ClaudeCode;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;

namespace AI.Sentinel.Tests.ClaudeCode;

public class DetectorPresetsTests
{
    private static HashSet<string> Ids(IEnumerable<IDetector> detectors) =>
        detectors.Select(d => d.Id.Value).ToHashSet(StringComparer.Ordinal);

    // Drift guard: ensures DetectorPresets.BuildAll() stays in sync with the concrete classes in the AI.Sentinel
    // assembly that AddAISentinel registers as IDetector singletons via ZeroAllocInject source-gen. If a new detector is
    // added in the assembly but not to BuildAll, this test fails loudly.
    [Fact]
    public void BuildAll_CountMatchesRegisteredIDetectorCount()
    {
        var detectorAssembly = typeof(IDetector).Assembly;

        var registeredCount = detectorAssembly.GetTypes()
            .Where(t => t is { IsClass: true, IsAbstract: false })
            .Count(t => t.GetCustomAttributes(inherit: false)
                .Any(a => a.GetType().Name.Contains("Singleton", StringComparison.Ordinal)
                       && a.GetType().GetProperty("As")?.GetValue(a) is Type asType
                       && asType == typeof(IDetector)));

        Assert.Equal(registeredCount, DetectorPresets.BuildAll().Length);
    }

    // Every preset that runs semantic security detectors also runs the Art. 5 compliance detectors.
    [Fact]
    public void BothPresets_IncludeTheComplianceDetectors()
    {
        string[] cmp = ["CMP-01", "CMP-02", "CMP-03", "CMP-04"];

        Assert.Subset(Ids(DetectorPresets.BuildSecurity()), cmp.ToHashSet(StringComparer.Ordinal));
        Assert.Subset(Ids(DetectorPresets.BuildAll()), cmp.ToHashSet(StringComparer.Ordinal));
    }

    // The redaction pass takes its redactors from the pipeline's detectors, so a redacting detector left out of the
    // default preset would silently stop redacting. SEC-23 was missing, so the proxy redacted secrets and no PII.
    [Fact]
    public void SecurityPreset_HoldsEveryRedactingDetector()
    {
        var redactors = Ids(DetectorPresets.BuildAll().Where(d => d is IRedactingDetector));

        Assert.Contains("SEC-23", redactors);
        Assert.Subset(Ids(DetectorPresets.BuildSecurity()), redactors);
    }

    // The proxy scans tool arguments and tool results, never a model's reply, which is what the response-quality
    // detectors judge.
    [Fact]
    public void SecurityPreset_HoldsNoResponseQualityDetector()
    {
        Assert.DoesNotContain(DetectorPresets.BuildSecurity(),
            d => d.Category is DetectorCategory.Operational or DetectorCategory.Hallucination);
        Assert.Equal(18, DetectorPresets.BuildSecurity().Length);
    }
}
