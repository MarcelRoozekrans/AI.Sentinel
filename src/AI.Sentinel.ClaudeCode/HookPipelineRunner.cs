using Microsoft.Extensions.AI;
using Microsoft.Extensions.DependencyInjection;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;

namespace AI.Sentinel.ClaudeCode;

/// <summary>
/// Vendor-agnostic pipeline runner for hook adapters. Takes the mapped
/// <see cref="ChatMessage"/> list, runs it through AI.Sentinel using
/// <see cref="SentinelPipeline.ScanMessagesAsync"/> (prompt-only — no inner
/// LLM call), and returns a <see cref="HookOutput"/>.
/// </summary>
/// <remarks>
/// Public so that other vendor adapters (e.g. <c>AI.Sentinel.Copilot</c>)
/// can call it after doing their own payload -> messages mapping.
/// </remarks>
public static class HookPipelineRunner
{
    /// <summary>Scans <paramref name="messages"/> prompt-only and maps the result to a hook decision.</summary>
    /// <param name="provider">Service provider with AI.Sentinel registered.</param>
    /// <param name="config">Severity-to-decision mapping and verbosity.</param>
    /// <param name="messages">The messages mapped from the hook payload.</param>
    /// <param name="sessionId">The raw session id string from the hook input, recorded on the audit entries.
    /// <see langword="null"/>, empty or whitespace means none, and a fresh id is minted for the call.
    /// The pipeline itself takes the <see cref="SessionId"/> domain type; this method converts.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>Allow when nothing was detected, otherwise the decision for the detected severity.</returns>
    public static async Task<HookOutput> RunAsync(
        IServiceProvider provider,
        HookConfig config,
        IReadOnlyList<ChatMessage> messages,
        string? sessionId,
        CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(provider);
        ArgumentNullException.ThrowIfNull(config);
        ArgumentNullException.ThrowIfNull(messages);

        // Build a pipeline bound to an unused inner client — ScanMessagesAsync
        // never invokes it, so the client shape is irrelevant.
        var pipeline = provider.BuildSentinelPipeline(UnusedChatClient.Instance);
        var error = await pipeline.ScanMessagesAsync(
            messages, null, string.IsNullOrWhiteSpace(sessionId) ? null : new SessionId(sessionId), ct).ConfigureAwait(false);

        if (error is SentinelError.ThreatDetected t)
        {
            var decision = HookSeverityMapper.Map(t.Result.Severity, config);
            var reason = $"{t.Result.DetectorId.Value} {t.Result.Severity}: {t.Result.Reason}";
            return new HookOutput(decision, reason);
        }

        // RateLimitExceeded and any other non-ThreatDetected error are not exposed
        // to hooks today — treat as Allow. Hook invocations don't honor rate limits
        // (they're not real LLM calls), so this path should be unreachable in practice.
        return new HookOutput(HookDecision.Allow, null);
    }

    // IChatClient satisfying BuildSentinelPipeline's signature. Never invoked.
    private sealed class UnusedChatClient : IChatClient
    {
        public static readonly UnusedChatClient Instance = new();
        public Task<ChatResponse> GetResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, CancellationToken cancellationToken = default)
            => throw new InvalidOperationException("UnusedChatClient should never be invoked — hook adapters use prompt-only scanning.");
        public IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, CancellationToken cancellationToken = default)
            => throw new InvalidOperationException("UnusedChatClient should never be invoked — hook adapters use prompt-only scanning.");
        public object? GetService(Type serviceType, object? key = null) => null;
        public void Dispose() { }
    }
}
