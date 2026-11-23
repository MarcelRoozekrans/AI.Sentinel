namespace AI.Sentinel.Tests.AspNetCore;

internal sealed class SettableTime(DateTimeOffset now) : TimeProvider
{
    public DateTimeOffset Now { get; set; } = now;

    public override DateTimeOffset GetUtcNow() => Now;
}
