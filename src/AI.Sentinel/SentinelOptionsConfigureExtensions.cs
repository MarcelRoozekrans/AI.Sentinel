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

    /// <summary>Disable an official detector by its type name (<c>"PromptInjectionDetector"</c>) or its
    /// id (<c>"SEC-01"</c>), matched case-sensitively. Needs no generic type argument or reflection, so it
    /// suits configuration-driven setups. Returns <see langword="false"/> and changes nothing when the
    /// value names no official detector.</summary>
    public static bool TryDisableDetector(this SentinelOptions opts, string nameOrId)
    {
        ArgumentNullException.ThrowIfNull(opts);
        ArgumentNullException.ThrowIfNull(nameOrId);

        if (!OfficialDetectors.TryResolve(nameOrId, out var detectorType))
        {
            return false;
        }

        opts.GetOrCreateDetectorConfiguration(detectorType).Enabled = false;
        return true;
    }

    /// <summary>Like <see cref="TryDisableDetector"/>, but throws <see cref="ArgumentException"/>
    /// when <paramref name="nameOrId"/> names no official detector.</summary>
    public static SentinelOptions DisableDetector(this SentinelOptions opts, string nameOrId)
    {
        if (!opts.TryDisableDetector(nameOrId))
        {
            throw new ArgumentException(
                $"'{nameOrId}' is not an official AI.Sentinel detector type name or id.",
                nameof(nameOrId));
        }

        return opts;
    }
}
