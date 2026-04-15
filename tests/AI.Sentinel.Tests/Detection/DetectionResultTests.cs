using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using Xunit;

namespace AI.Sentinel.Tests.Detection;

public class DetectionResultTests
{
    [Fact] public void Clean_HasSeverityNone() =>
        Assert.Equal(Severity.None, DetectionResult.Clean(new DetectorId("SEC-01")).Severity);

    [Fact] public void WithSeverity_CriticalPreservesReason()
    {
        var r = DetectionResult.WithSeverity(new DetectorId("SEC-01"), Severity.Critical, "prompt injection detected");
        Assert.Equal(Severity.Critical, r.Severity);
        Assert.Equal("prompt injection detected", r.Reason);
    }
}
