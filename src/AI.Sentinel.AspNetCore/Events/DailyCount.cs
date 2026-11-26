namespace AI.Sentinel.AspNetCore.Events;

/// <summary>How many events of one outcome an organisation received on one UTC day.</summary>
internal sealed record DailyCount(DateOnly Day, string Outcome, int Count);
