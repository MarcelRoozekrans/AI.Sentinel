using Xunit;

namespace AI.Sentinel.Tests.Telemetry;

public class SentinelMetricsTests
{
    [Fact]
    public void Meter_Name_IsAiSentinel()
    {
        Assert.Equal("ai.sentinel", AI.Sentinel.SentinelMetrics.Meter.Name);
    }

    [Fact]
    public void Counters_AreReachable()
    {
        Assert.NotNull(AI.Sentinel.SentinelMetrics.Threats);
        Assert.NotNull(AI.Sentinel.SentinelMetrics.RateLimited);
        Assert.NotNull(AI.Sentinel.SentinelMetrics.AlertsSuppressed);
    }
}
