namespace AI.Sentinel.Alerts;

/// <summary>A no-op <see cref="IAlertSink"/> implementation that discards all alerts (null-object pattern).</summary>
public sealed class NullAlertSink : IAlertSink
{
    /// <summary>The shared singleton instance of <see cref="NullAlertSink"/>.</summary>
    public static readonly NullAlertSink Instance = new();
    public ValueTask SendAsync(SentinelError error, CancellationToken ct) => ValueTask.CompletedTask;
}
