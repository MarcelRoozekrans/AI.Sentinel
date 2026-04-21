using ZeroAlloc.Telemetry;

namespace AI.Sentinel.Alerts;

/// <summary>Dispatches alert notifications when a threat is detected or the pipeline fails.</summary>
/// <remarks>Implementations are expected to be fire-and-forget; errors must be swallowed so they never surface to the caller.</remarks>
[Instrument("ai.sentinel")]
public interface IAlertSink
{
    /// <summary>Sends an alert for the given <paramref name="error"/> to the underlying notification channel.</summary>
    /// <param name="error">The sentinel error that triggered the alert.</param>
    /// <param name="ct">Cancellation token for the send operation.</param>
    [Trace("alert.send")]
    [Count("alert.sends")]
    ValueTask SendAsync(SentinelError error, CancellationToken ct);
}
