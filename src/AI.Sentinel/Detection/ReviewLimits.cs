namespace AI.Sentinel.Detection;

/// <summary>How many detections one scan may send to the <see cref="IDetectionReviewer"/>, and how long each review may take.</summary>
/// <param name="MaxPerScan">The most reviews per scan; 0 disables review.</param>
/// <param name="Timeout">The longest one review may take before its detection keeps its capped result.</param>
/// <param name="Clock">The clock that times <paramref name="Timeout"/>; <see langword="null"/> is the system clock.
/// A seam for tests, so a timeout does not depend on how fast the machine is.</param>
internal sealed record ReviewLimits(int MaxPerScan, TimeSpan Timeout, TimeProvider? Clock = null)
{
    /// <summary>Four reviews per scan, five seconds each.</summary>
    public static ReviewLimits Default { get; } = new(4, TimeSpan.FromSeconds(5));

    /// <summary>The clock that times the review timeout.</summary>
    public TimeProvider TimeProvider => Clock ?? TimeProvider.System;
}
