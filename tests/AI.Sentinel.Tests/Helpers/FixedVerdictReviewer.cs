using AI.Sentinel.Detection;

namespace AI.Sentinel.Tests.Helpers;

/// <summary>A reviewer that answers every request with one severity, after an optional delay that honours cancellation, and counts the requests.</summary>
public sealed class FixedVerdictReviewer(Severity severity, TimeSpan? delay = null) : IDetectionReviewer
{
    private int _calls;

    /// <summary>How many reviews were requested.</summary>
    public int Calls => Volatile.Read(ref _calls);

    public async ValueTask<ReviewVerdict> ReviewAsync(ReviewRequest request, CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref _calls);
        if (delay is { } wait) await Task.Delay(wait, cancellationToken);
        return new ReviewVerdict(severity, "confirmed by test");
    }
}
