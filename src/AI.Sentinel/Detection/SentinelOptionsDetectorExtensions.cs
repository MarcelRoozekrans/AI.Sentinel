using System.Diagnostics.CodeAnalysis;

namespace AI.Sentinel.Detection;

/// <summary>Extension methods on <see cref="SentinelOptions"/> for registering custom <see cref="IDetector"/> implementations.</summary>
public static class SentinelOptionsDetectorExtensions
{
    /// <summary>Registers a custom <see cref="IDetector"/> alongside the auto-registered official detectors.</summary>
    /// <typeparam name="T">The detector implementation type.</typeparam>
    /// <param name="opts">The Sentinel options to configure.</param>
    /// <returns>The same <see cref="SentinelOptions"/> instance, to support fluent chaining.</returns>
    /// <remarks>Singleton lifetime. The detector is constructed via DI — its constructor parameters must be resolvable from the host's <see cref="IServiceProvider"/>.</remarks>
    public static SentinelOptions AddDetector<
        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] T>(
        this SentinelOptions opts) where T : class, IDetector
    {
        ArgumentNullException.ThrowIfNull(opts);
        opts.AddDetectorRegistration(new SentinelOptions.DetectorRegistration(typeof(T), Factory: null));
        return opts;
    }

    /// <summary>Registers a custom <see cref="IDetector"/> via a custom factory. Use when your detector needs DI services other than what's resolvable by the default activator.</summary>
    /// <typeparam name="T">The detector implementation type.</typeparam>
    /// <param name="opts">The Sentinel options to configure.</param>
    /// <param name="factory">Factory that produces the detector instance from the resolved <see cref="IServiceProvider"/>.</param>
    /// <returns>The same <see cref="SentinelOptions"/> instance, to support fluent chaining.</returns>
    public static SentinelOptions AddDetector<T>(this SentinelOptions opts, Func<IServiceProvider, T> factory) where T : class, IDetector
    {
        ArgumentNullException.ThrowIfNull(opts);
        ArgumentNullException.ThrowIfNull(factory);
        opts.AddDetectorRegistration(new SentinelOptions.DetectorRegistration(typeof(T), sp => factory(sp)));
        return opts;
    }
}
