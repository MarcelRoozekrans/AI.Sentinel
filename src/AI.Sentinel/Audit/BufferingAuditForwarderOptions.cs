namespace AI.Sentinel.Audit;

/// <summary>Configuration for <see cref="BufferingAuditForwarder{TInner}"/>.</summary>
public sealed class BufferingAuditForwarderOptions
{
    /// <summary>Maximum entries per batch before forced flush. Default 100.</summary>
    public int MaxBatchSize { get; set; } = 100;

    /// <summary>Maximum time between flushes regardless of batch size. Default 5 seconds.</summary>
    public TimeSpan MaxFlushInterval { get; set; } = TimeSpan.FromSeconds(5);

    /// <summary>Maximum entries buffered before drops occur. Default 10 000.</summary>
    public int ChannelCapacity { get; set; } = 10_000;
}
