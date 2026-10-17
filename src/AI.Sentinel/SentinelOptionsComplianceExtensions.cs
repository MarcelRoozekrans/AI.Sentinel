using AI.Sentinel.Detectors.Compliance;

namespace AI.Sentinel;

public static class SentinelOptionsComplianceExtensions
{
    /// <summary>Turns on the four Art. 5 compliance detectors, CMP-01 to CMP-04, which are off by default.
    /// The same as <c>opts.Configure&lt;T&gt;(c =&gt; c.Enabled = true)</c> for each of them.</summary>
    /// <remarks>They are semantic, so they also need <see cref="SentinelOptions.EmbeddingGenerator"/>. Their
    /// thresholds are tuned on <c>all-MiniLM-L6-v2</c>; with another embedding model, set
    /// <see cref="Detection.DetectorConfiguration.HighThreshold"/> and
    /// <see cref="Detection.DetectorConfiguration.MediumThreshold"/> for that model.</remarks>
    public static SentinelOptions EnableComplianceDetectors(this SentinelOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        return options.ConfigureComplianceDetectors(Enable);
    }

    private static void Enable(Detection.DetectorConfiguration c) => c.Enabled = true;
}
