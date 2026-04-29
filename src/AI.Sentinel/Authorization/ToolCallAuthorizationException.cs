using AI.Sentinel.Detection;
using AI.Sentinel.Intervention;

namespace AI.Sentinel.Authorization;

/// <summary>Thrown by the in-process surface when a tool call is denied by an <see cref="IAuthorizationPolicy"/>.</summary>
public sealed class ToolCallAuthorizationException : SentinelException
{
    /// <summary>Initializes an exception without a decision (standard ctor).</summary>
    public ToolCallAuthorizationException() { }

    /// <summary>Initializes an exception with a custom message.</summary>
    /// <param name="message">The error message.</param>
    public ToolCallAuthorizationException(string message) : base(message) { }

    /// <summary>Initializes an exception with a custom message and inner exception.</summary>
    /// <param name="message">The error message.</param>
    /// <param name="innerException">The inner exception.</param>
    public ToolCallAuthorizationException(string message, Exception innerException)
        : base(message, innerException) { }

    /// <summary>Initializes an exception with a custom message and pipeline result (mirrors <see cref="SentinelException"/>).</summary>
    /// <param name="message">The error message.</param>
    /// <param name="result">The pipeline result associated with the failure.</param>
    public ToolCallAuthorizationException(string message, PipelineResult result)
        : base(message, result) { }

    /// <summary>Creates an exception that wraps an <see cref="AuthorizationDecision"/> deny result.</summary>
    /// <param name="decision">The denial decision (policy name + reason).</param>
    public ToolCallAuthorizationException(AuthorizationDecision decision)
        : base(BuildMessage(decision))
    {
        Decision = decision!;
    }

    private static string BuildMessage(AuthorizationDecision? decision) =>
        decision is AuthorizationDecision.DenyDecision deny
            ? $"Tool call denied by policy '{deny.PolicyName}': {deny.Reason}"
            : "Tool call denied";

    /// <summary>The denial decision (policy name + reason). May be <c>null</c> when constructed via the message-only constructors.</summary>
    public AuthorizationDecision? Decision { get; }
}
