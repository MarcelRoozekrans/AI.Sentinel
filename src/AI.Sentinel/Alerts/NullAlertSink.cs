namespace AI.Sentinel.Alerts;

public sealed class NullAlertSink : IAlertSink
{
    public static readonly NullAlertSink Instance = new();
    public ValueTask SendAsync(SentinelError error, CancellationToken ct) => ValueTask.CompletedTask;
}
