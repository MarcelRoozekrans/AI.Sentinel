using Microsoft.Extensions.AI;
using ZeroAlloc.Validation;
using AI.Sentinel.Authorization;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;

namespace AI.Sentinel;

// [Validate] — will emit SentinelOptionsValidator when ZeroAlloc.Validation source generator ships
[Validate]
public sealed class SentinelOptions
{
    private readonly List<ToolCallPolicyBinding> _authorizationBindings = new();

    /// <summary>Behaviour when a tool call has no matching policy binding. Defaults to <see cref="ToolPolicyDefault.Allow"/>.</summary>
    public ToolPolicyDefault DefaultToolPolicy { get; set; } = ToolPolicyDefault.Allow;

    /// <summary>Internal access for the guard at construction time.</summary>
    internal IReadOnlyList<ToolCallPolicyBinding> GetAuthorizationBindings() => _authorizationBindings;

    /// <summary>Internal hook for the <c>RequireToolPolicy</c> extension.</summary>
    internal void AddAuthorizationBinding(ToolCallPolicyBinding binding) => _authorizationBindings.Add(binding);

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

    /// <summary>Inactivity window after which per-session dedup state and rate-limiter
    /// buckets are evicted from in-memory dictionaries. Default: 1 hour.
    /// Increase for long-lived sessions; decrease for very high-cardinality session keys.</summary>
    public TimeSpan SessionIdleTimeout { get; set; } = TimeSpan.FromHours(1);

    /// <summary>Optional expected response type for structured-output LLM calls.
    /// When set, <c>OutputSchemaDetector</c> (SEC-29) attempts to deserialize each assistant
    /// response as this type via the registered <c>ISerializerDispatcher</c>.
    /// The type must be annotated with <c>[ZeroAllocSerializable(SerializationFormat.SystemTextJson)]</c>.
    /// <c>null</c> (default) disables the detector.</summary>
    public Type? ExpectedResponseType { get; set; }

    /// <summary>
    /// Optional embedding generator. When set, all semantic detectors use
    /// cosine similarity against pre-computed threat phrase embeddings instead
    /// of regex. If null, semantic detectors return Clean.
    /// </summary>
    public IEmbeddingGenerator<string, Embedding<float>>? EmbeddingGenerator { get; set; }

    /// <summary>
    /// Cache for scan-time message embeddings. Defaults to an in-memory LRU
    /// cache (1024 entries). Implement <see cref="IEmbeddingCache"/> to plug in
    /// a persistent store (Redis, SQLite, etc.).
    /// </summary>
    public IEmbeddingCache? EmbeddingCache { get; set; }

    public SentinelAction ActionFor(Detection.Severity severity) => severity switch
    {
        Detection.Severity.Critical => OnCritical,
        Detection.Severity.High     => OnHigh,
        Detection.Severity.Medium   => OnMedium,
        Detection.Severity.Low      => OnLow,
        _                           => SentinelAction.PassThrough
    };
}
