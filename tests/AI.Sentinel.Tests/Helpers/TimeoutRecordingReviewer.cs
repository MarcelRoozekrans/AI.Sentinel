using System.Diagnostics;
using AI.Sentinel.Detection;

namespace AI.Sentinel.Tests.Helpers;

/// <summary>A reviewer that never answers: it waits until its token is cancelled and records how long that took, so a
/// host test can tell which review timeout applied without racing a reply against it.</summary>
/// <remarks>A timer never fires early, so the shortest recorded wait is a lower bound on the timeout that holds on a
/// loaded machine too; a late timer only makes it longer.</remarks>
public sealed class TimeoutRecordingReviewer : IDetectionReviewer
{
    private readonly TaskCompletionSource<TimeSpan> _firstCancelled = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private int _calls;

    /// <summary>How many reviews were requested.</summary>
    public int Calls => Volatile.Read(ref _calls);

    public async ValueTask<ReviewVerdict> ReviewAsync(ReviewRequest request, CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref _calls);
        var started = Stopwatch.GetTimestamp();
        try
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
        }
        finally
        {
            _firstCancelled.TrySetResult(Stopwatch.GetElapsedTime(started));
        }

        return ReviewVerdict.None;
    }

    /// <summary>The time from the first cancelled review's start to its cancellation. Fails after 30 s, when no review
    /// was cancelled at all.</summary>
    public Task<TimeSpan> ElapsedUntilCancelledAsync() => _firstCancelled.Task.WaitAsync(TimeSpan.FromSeconds(30));
}
