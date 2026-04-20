using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using AI.Sentinel.Intervention;
using Xunit;

namespace AI.Sentinel.Tests;

public class SentinelErrorTests
{
    [Fact]
    public void ThreatDetected_ToException_ReturnsSentinelException()
    {
        var result = DetectionResult.WithSeverity(new DetectorId("SEC-01"), Severity.High, "test");
        var error = new SentinelError.ThreatDetected(result, SentinelAction.Quarantine);
        var ex = error.ToException();
        Assert.IsType<SentinelException>(ex);
        Assert.Contains("SEC-01", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void PipelineFailure_ToException_ReturnsException()
    {
        var error = new SentinelError.PipelineFailure("something went wrong");
        var ex = error.ToException();
        Assert.Contains("something went wrong", ex.Message, StringComparison.Ordinal);
    }
}
