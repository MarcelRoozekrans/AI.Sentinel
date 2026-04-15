using Microsoft.Extensions.AI;
using ZeroAlloc.Validation;
using AI.Sentinel.Domain;

namespace AI.Sentinel;

public sealed class SentinelOptionsValidator
{
    public ValidationResult Validate(SentinelOptions opts)
    {
        if (opts.AuditCapacity <= 0)
            return new ValidationResult([new ValidationFailure
            {
                ErrorMessage = "AuditCapacity must be greater than 0",
                ErrorCode    = "GreaterThan"
            }]);
        return new ValidationResult([]);
    }
}

[Validate]
public sealed class SentinelOptions
{
    /// <summary>Optional secondary IChatClient used for LLM escalation on borderline detections.</summary>
    public IChatClient? EscalationClient { get; set; }

    [GreaterThan(0)]
    public int AuditCapacity { get; set; } = 10_000;

    public SentinelAction OnCritical { get; set; } = SentinelAction.Quarantine;
    public SentinelAction OnHigh     { get; set; } = SentinelAction.Alert;
    public SentinelAction OnMedium   { get; set; } = SentinelAction.Log;
    public SentinelAction OnLow      { get; set; } = SentinelAction.Log;

    public AgentId DefaultSenderId   { get; set; } = new("unknown-sender");
    public AgentId DefaultReceiverId { get; set; } = new("unknown-receiver");

    public SentinelAction ActionFor(Detection.Severity severity) => severity switch
    {
        Detection.Severity.Critical => OnCritical,
        Detection.Severity.High     => OnHigh,
        Detection.Severity.Medium   => OnMedium,
        Detection.Severity.Low      => OnLow,
        _                           => SentinelAction.PassThrough
    };
}
