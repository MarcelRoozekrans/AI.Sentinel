namespace AI.Sentinel.AspNetCore;

/// <summary>How long one organisation's events and daily counts are kept. Older data is deleted.</summary>
public sealed class ServerEventRetention
{
    /// <summary>Days an event is kept. Defaults to 90.</summary>
    public int EventDays { get; set; } = 90;

    /// <summary>Months a daily count is kept. Defaults to 13.</summary>
    public int DailyCountMonths { get; set; } = 13;
}
