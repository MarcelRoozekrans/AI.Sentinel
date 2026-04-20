using AI.Sentinel.Alerts;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using Xunit;

namespace AI.Sentinel.Tests.Alerts;

public class AlertSinkTests
{
    [Fact]
    public async Task NullAlertSink_DoesNotThrow()
    {
        var error = new SentinelError.ThreatDetected(
            DetectionResult.WithSeverity(new DetectorId("SEC-01"), Severity.High, "test"),
            SentinelAction.Quarantine);
        await NullAlertSink.Instance.SendAsync(error, default);
        // reaching here confirms no throw
    }

    [Fact]
    public async Task NullAlertSink_PipelineFailure_DoesNotThrow()
    {
        var error = new SentinelError.PipelineFailure("network error");
        await NullAlertSink.Instance.SendAsync(error, default);
    }

    [Fact]
    public async Task WebhookAlertSink_UnreachableEndpoint_DoesNotThrow()
    {
        // Endpoint is deliberately unreachable — webhook failures must never surface to caller.
        var sink = new WebhookAlertSink(new Uri("http://localhost:19999/nonexistent"));
        var error = new SentinelError.ThreatDetected(
            DetectionResult.WithSeverity(new DetectorId("SEC-01"), Severity.High, "test"),
            SentinelAction.Alert);
        await sink.SendAsync(error, default);
        // reaching here confirms the exception was swallowed
    }
}
