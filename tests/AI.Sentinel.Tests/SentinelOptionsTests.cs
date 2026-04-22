using Xunit;
using AI.Sentinel;
using AI.Sentinel.Detection;

namespace AI.Sentinel.Tests;

public class SentinelOptionsTests
{
    [Fact] public void DefaultOptions_AreValid()
    {
        var opts = new SentinelOptions();
        var validator = new SentinelOptionsValidator();
        var result = validator.Validate(opts);
        Assert.True(result.IsValid);
    }

    [Fact] public void AuditCapacity_BelowMinimum_IsInvalid()
    {
        var opts = new SentinelOptions { AuditCapacity = 0 };
        var validator = new SentinelOptionsValidator();
        Assert.False(validator.Validate(opts).IsValid);
    }

    [Fact] public void ActionFor_ReturnsMappedAction()
    {
        var opts = new SentinelOptions { OnCritical = SentinelAction.Quarantine };
        Assert.Equal(SentinelAction.Quarantine, opts.ActionFor(Severity.Critical));
        Assert.Equal(SentinelAction.PassThrough, opts.ActionFor(Severity.None));
    }

    [Fact]
    public void AlertDeduplicationWindow_DefaultsToNull()
    {
        var opts = new SentinelOptions();
        Assert.Null(opts.AlertDeduplicationWindow);
    }

    [Fact]
    public void MaxCallsPerSecond_And_BurstSize_DefaultToNull()
    {
        var opts = new SentinelOptions();
        Assert.Null(opts.MaxCallsPerSecond);
        Assert.Null(opts.BurstSize);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void MaxCallsPerSecond_ZeroOrNegative_IsInvalid(int value)
    {
        var opts = new SentinelOptions { MaxCallsPerSecond = value };
        Assert.False(new SentinelOptionsValidator().Validate(opts).IsValid);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void BurstSize_ZeroOrNegative_IsInvalid(int value)
    {
        var opts = new SentinelOptions { BurstSize = value };
        Assert.False(new SentinelOptionsValidator().Validate(opts).IsValid);
    }

    [Fact]
    public void SessionIdleTimeout_DefaultsToOneHour()
    {
        var opts = new SentinelOptions();
        Assert.Equal(TimeSpan.FromHours(1), opts.SessionIdleTimeout);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void SessionIdleTimeout_ZeroOrNegative_IsInvalid(int seconds)
    {
        var opts = new SentinelOptions { SessionIdleTimeout = TimeSpan.FromSeconds(seconds) };
        Assert.False(new SentinelOptionsValidator().Validate(opts).IsValid);
    }
}
