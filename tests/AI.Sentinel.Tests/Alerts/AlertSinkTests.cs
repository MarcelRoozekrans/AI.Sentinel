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
}
