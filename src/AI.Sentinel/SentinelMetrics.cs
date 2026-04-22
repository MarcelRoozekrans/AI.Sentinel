using System.Diagnostics.Metrics;

namespace AI.Sentinel;

/// <summary>Central owner of the <c>ai.sentinel</c> meter and all hand-written counters.
/// Source-generator-emitted counters (from ZeroAlloc.Telemetry <c>[Instrument]</c> proxies)
/// live in their generated code and are not duplicated here.</summary>
internal static class SentinelMetrics
{
    internal static readonly Meter Meter = new("ai.sentinel");

    internal static readonly Counter<long> Threats =
        Meter.CreateCounter<long>("sentinel.threats");

    internal static readonly Counter<long> RateLimited =
        Meter.CreateCounter<long>("sentinel.rate_limit.exceeded");

    internal static readonly Counter<long> AlertsSuppressed =
        Meter.CreateCounter<long>("sentinel.alerts.suppressed");
}
