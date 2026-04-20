namespace AI.Sentinel.Alerts;

public interface IAlertSink
{
    ValueTask SendAsync(SentinelError error, CancellationToken ct);
}
