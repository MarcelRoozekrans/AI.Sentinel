namespace AI.Sentinel.Screening;

/// <summary>
/// Screens text through a registered AI.Sentinel pipeline without a chat call. Resolve it from DI after
/// <c>AddAISentinel</c>: unkeyed for the default pipeline, keyed by name for a named one.
/// </summary>
public interface ISentinelScreener
{
    /// <summary>Screens <paramref name="text"/> and returns the verdict; see <see cref="SentinelPipeline.ScreenAsync"/>.</summary>
    /// <param name="text">The text to screen.</param>
    /// <param name="options">Per-call options, or <see langword="null"/> for the defaults.</param>
    /// <param name="ct">Cancels the scan.</param>
    ValueTask<ScreeningOutcome> ScreenAsync(string text, ScreeningOptions? options = null, CancellationToken ct = default);
}
