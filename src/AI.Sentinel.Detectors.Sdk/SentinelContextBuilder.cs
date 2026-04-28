using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using Microsoft.Extensions.AI;

namespace AI.Sentinel.Detectors.Sdk;

/// <summary>
/// Fluent builder for constructing <see cref="SentinelContext"/> instances in tests for custom detectors.
/// </summary>
/// <remarks>
/// Defaults: <c>SenderId</c> = <c>"user"</c>, <c>ReceiverId</c> = <c>"assistant"</c>,
/// <c>SessionId</c> = a fresh <see cref="SessionId.New()"/>, empty <c>Messages</c>, empty <c>History</c>,
/// <c>LlmId</c> = <c>null</c>. Override any of these with the <c>WithXxx</c> methods.
/// </remarks>
public sealed class SentinelContextBuilder
{
    private AgentId _sender = new("user");
    private AgentId _receiver = new("assistant");
    private SessionId _session = SessionId.New();
    private readonly List<ChatMessage> _messages = new();
    private readonly List<AuditEntry> _history = new();
    private string? _llmId;

    /// <summary>Appends a <see cref="ChatRole.User"/> message with the given text.</summary>
    public SentinelContextBuilder WithUserMessage(string text)
    {
        _messages.Add(new ChatMessage(ChatRole.User, text));
        return this;
    }

    /// <summary>Appends a <see cref="ChatRole.Assistant"/> message with the given text.</summary>
    public SentinelContextBuilder WithAssistantMessage(string text)
    {
        _messages.Add(new ChatMessage(ChatRole.Assistant, text));
        return this;
    }

    /// <summary>Appends a <see cref="ChatRole.Tool"/> message with the given text.</summary>
    public SentinelContextBuilder WithToolMessage(string text)
    {
        _messages.Add(new ChatMessage(ChatRole.Tool, text));
        return this;
    }

    /// <summary>Appends an arbitrary <see cref="ChatMessage"/>, preserving role and content as-is.</summary>
    public SentinelContextBuilder WithMessage(ChatMessage message)
    {
        ArgumentNullException.ThrowIfNull(message);
        _messages.Add(message);
        return this;
    }

    /// <summary>Overrides the default <see cref="SessionId"/>.</summary>
    public SentinelContextBuilder WithSession(SessionId session)
    {
        ArgumentNullException.ThrowIfNull(session);
        _session = session;
        return this;
    }

    /// <summary>Overrides the default sender <see cref="AgentId"/> (default: <c>"user"</c>).</summary>
    public SentinelContextBuilder WithSender(AgentId sender)
    {
        ArgumentNullException.ThrowIfNull(sender);
        _sender = sender;
        return this;
    }

    /// <summary>Overrides the default receiver <see cref="AgentId"/> (default: <c>"assistant"</c>).</summary>
    public SentinelContextBuilder WithReceiver(AgentId receiver)
    {
        ArgumentNullException.ThrowIfNull(receiver);
        _receiver = receiver;
        return this;
    }

    /// <summary>Appends an entry to the audit history surfaced to detectors via <see cref="SentinelContext.History"/>.</summary>
    public SentinelContextBuilder WithHistoryEntry(AuditEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        _history.Add(entry);
        return this;
    }

    /// <summary>Sets the optional LLM identifier exposed via <see cref="SentinelContext.LlmId"/>.</summary>
    public SentinelContextBuilder WithLlmId(string? llmId)
    {
        _llmId = llmId;
        return this;
    }

    /// <summary>Builds an immutable <see cref="SentinelContext"/> from the configured values.</summary>
    public SentinelContext Build()
        => new(_sender, _receiver, _session, _messages.ToArray(), _history.ToArray(), _llmId);
}
