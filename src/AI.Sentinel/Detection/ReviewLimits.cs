using System.Runtime.InteropServices;

namespace AI.Sentinel.Detection;

/// <summary>How many detections one scan may send to the <see cref="IDetectionReviewer"/>, and how long each review may take.</summary>
/// <param name="MaxPerScan">The most reviews per scan; 0 disables review.</param>
/// <param name="Timeout">The longest one review may take before its detection keeps its capped result.</param>
[StructLayout(LayoutKind.Auto)]
internal readonly record struct ReviewLimits(int MaxPerScan, TimeSpan Timeout)
{
    /// <summary>Four reviews per scan, five seconds each.</summary>
    public static ReviewLimits Default => new(4, TimeSpan.FromSeconds(5));
}
