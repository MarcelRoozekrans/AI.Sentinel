using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using AI.Sentinel.Intervention;
using Xunit;

namespace AI.Sentinel.Tests;

public class SentinelErrorTests
{
    [Fact]
    public void ThreatDetected_ExposesSessionId()
    {
        var sessionId = SessionId.New();
        var error = new SentinelError.ThreatDetected(
            DetectionResult.WithSeverity(new DetectorId("SEC-01"), Severity.High, "test"),
            SentinelAction.Quarantine,
            sessionId);
        Assert.Equal(sessionId, error.Session);
    }

    [Fact]
    public void ThreatDetected_ToException_ReturnsSentinelException()
    {
        var result = DetectionResult.WithSeverity(new DetectorId("SEC-01"), Severity.High, "test");
        var error = new SentinelError.ThreatDetected(result, SentinelAction.Quarantine, SessionId.New());
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

    [Fact]
    public void RateLimitExceeded_ToException_ReturnsSentinelException()
    {
        var error = new SentinelError.RateLimitExceeded("user-42");
        var ex = error.ToException();
        var sentinelEx = Assert.IsType<SentinelException>(ex);
        Assert.Contains("user-42", sentinelEx.Message, StringComparison.Ordinal);
    }
}
