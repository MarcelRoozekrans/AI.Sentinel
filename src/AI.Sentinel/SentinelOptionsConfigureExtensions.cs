using AI.Sentinel.Detection;

namespace AI.Sentinel;

public static class SentinelOptionsConfigureExtensions
{
    /// <summary>Tune or disable a registered detector. Multiple calls for the same <typeparamref name="T"/>
    /// merge by mutation — each call's lambda runs against the same <see cref="DetectorConfiguration"/>
    /// instance, so independent properties accumulate and same-property writes are last-wins.
    /// <para>
    /// Validation: <see cref="DetectorConfiguration.SeverityFloor"/> must be less than or equal to
    /// <see cref="DetectorConfiguration.SeverityCap"/> when both are set; violations throw
    /// <see cref="ArgumentException"/> at the call site.
    /// </para>
    /// <para>
    /// Configuring a detector type that was never registered is a silent no-op — the type-keyed
    /// lookup simply doesn't fire at runtime.
    /// </para>
    /// </summary>
    public static SentinelOptions Configure<T>(this SentinelOptions opts, Action<DetectorConfiguration> configure)
        where T : IDetector
    {
        ArgumentNullException.ThrowIfNull(opts);
        ArgumentNullException.ThrowIfNull(configure);

        var cfg = opts.GetOrCreateDetectorConfiguration(typeof(T));
        configure(cfg);

        if (cfg.SeverityFloor is { } floor && cfg.SeverityCap is { } cap && floor > cap)
        {
            throw new ArgumentException(
                $"DetectorConfiguration for '{typeof(T).Name}' has SeverityFloor ({floor}) > SeverityCap ({cap}). Floor must be <= Cap.",
                nameof(configure));
        }

        return opts;
    }
}
