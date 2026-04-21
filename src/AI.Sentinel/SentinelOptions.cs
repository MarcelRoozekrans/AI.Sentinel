using Microsoft.Extensions.AI;
using ZeroAlloc.Validation;
using AI.Sentinel.Domain;

namespace AI.Sentinel;

// [Validate] — will emit SentinelOptionsValidator when ZeroAlloc.Validation source generator ships
[Validate]
public sealed class SentinelOptions
{
    /// <summary>Optional secondary IChatClient used for LLM escalation on borderline detections.</summary>
    public IChatClient? EscalationClient { get; set; }

    // [GreaterThan(0)] — enforced by SentinelOptionsValidator (ZeroAlloc.Validation source gen not yet available in v0.2.3)
    [GreaterThan(0)]
    public int AuditCapacity { get; set; } = 10_000;

    public SentinelAction OnCritical { get; set; } = SentinelAction.Quarantine;
    public SentinelAction OnHigh     { get; set; } = SentinelAction.Alert;
    public SentinelAction OnMedium   { get; set; } = SentinelAction.Log;
    public SentinelAction OnLow      { get; set; } = SentinelAction.Log;

    public AgentId DefaultSenderId   { get; set; } = new("unknown-sender");
    public AgentId DefaultReceiverId { get; set; } = new("unknown-receiver");

    /// <summary>Optional webhook URL to which alert payloads are POSTed when a threat is detected or the pipeline fails.</summary>
    public Uri? AlertWebhook { get; set; }

    /// <summary>Suppression window for repeated alerts from the same detector in the same session.
    /// <c>null</c> (default) suppresses for the entire session lifetime.
    /// Set to a <see cref="TimeSpan"/> to re-alert after the window expires.
    /// This value is read once at DI registration time; changes after <c>AddAISentinel</c> returns have no effect.</summary>
    public TimeSpan? AlertDeduplicationWindow { get; set; }

    /// <summary>Maximum LLM calls per second per session (token-bucket steady state).
    /// Null (default) = no rate limiting. Pair with <see cref="BurstSize"/> to allow
    /// initial spikes while capping sustained throughput.
    /// Uses <c>ZeroAlloc.Resilience.RateLimiter</c> — one bucket per session key.</summary>
    [GreaterThan(0)]
    public int? MaxCallsPerSecond { get; set; }

    /// <summary>Burst capacity — initial and maximum token count for the per-session rate limiter.
    /// Defaults to <see cref="MaxCallsPerSecond"/> when null.
    /// Set higher than <see cref="MaxCallsPerSecond"/> to absorb short spikes without throttling.</summary>
    [GreaterThan(0)]
    public int? BurstSize { get; set; }

    public SentinelAction ActionFor(Detection.Severity severity) => severity switch
    {
        Detection.Severity.Critical => OnCritical,
        Detection.Severity.High     => OnHigh,
        Detection.Severity.Medium   => OnMedium,
        Detection.Severity.Low      => OnLow,
        _                           => SentinelAction.PassThrough
    };
}
