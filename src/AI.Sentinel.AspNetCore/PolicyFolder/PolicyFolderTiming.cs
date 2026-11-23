namespace AI.Sentinel.AspNetCore.PolicyFolder;

/// <summary>How long the loader waits: for changes to settle, between polls, and between the retries of a failed pass.</summary>
internal sealed record PolicyFolderTiming(
    TimeSpan Settle, TimeSpan PollInterval, TimeSpan BackoffBase, TimeSpan BackoffMax, int MaxAttempts)
{
    public static readonly PolicyFolderTiming Default = new(
        TimeSpan.FromMilliseconds(500), TimeSpan.FromSeconds(30), TimeSpan.FromMilliseconds(250), TimeSpan.FromSeconds(30), 8);

    /// <summary>The wait before retry number <paramref name="attempt"/>, counted from 0: doubling, never above <see cref="BackoffMax"/>.</summary>
    public TimeSpan Backoff(int attempt)
    {
        var factor = Math.Pow(2, Math.Min(attempt, 30));
        var ticks = Math.Min(BackoffBase.Ticks * factor, BackoffMax.Ticks);
        return TimeSpan.FromTicks((long)ticks);
    }
}
