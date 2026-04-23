using Microsoft.Extensions.AI;

namespace AI.Sentinel.ClaudeCode;

/// <summary>
/// Vendor-agnostic pipeline runner for hook adapters. Takes the mapped
/// <see cref="ChatMessage"/> list, runs it through AI.Sentinel, and
/// returns a <see cref="HookOutput"/>.
/// </summary>
/// <remarks>
/// Public so that other vendor adapters (e.g. <c>AI.Sentinel.Copilot</c>)
/// can call it after doing their own payload -> messages mapping.
/// </remarks>
public static class HookPipelineRunner
{
    public static async Task<HookOutput> RunAsync(
        IServiceProvider provider,
        HookConfig config,
        IReadOnlyList<ChatMessage> messages,
        CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(provider);
        ArgumentNullException.ThrowIfNull(config);
        ArgumentNullException.ThrowIfNull(messages);

        var pipeline = provider.BuildSentinelPipeline(new NullChatClient());
        var result = await pipeline.GetResponseResultAsync(messages, null, ct).ConfigureAwait(false);

        if (result.IsFailure && result.Error is SentinelError.ThreatDetected t)
        {
            var decision = HookSeverityMapper.Map(t.Result.Severity, config);
            var reason = $"{t.Result.DetectorId} {t.Result.Severity}: {t.Result.Reason}";
            return new HookOutput(decision, reason);
        }

        return new HookOutput(HookDecision.Allow, null);
    }

    // Benign placeholder returned by NullChatClient. Hooks don't invoke an LLM,
    // so the pipeline's response scan sees this text. It must be long enough
    // to avoid OPS-01 (BlankResponseDetector) Medium/Low severities and
    // bland enough not to trigger other detectors.
    private const string NullResponseText = "Hook adapter placeholder response.";

    private sealed class NullChatClient : IChatClient
    {
        public Task<ChatResponse> GetResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, CancellationToken cancellationToken = default)
            => Task.FromResult(new ChatResponse([new ChatMessage(ChatRole.Assistant, NullResponseText)]));
        public IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();
        public object? GetService(Type serviceType, object? key = null) => null;
        public void Dispose() { }
    }
}
