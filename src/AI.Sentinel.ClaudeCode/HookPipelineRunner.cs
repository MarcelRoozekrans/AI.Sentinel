using Microsoft.Extensions.AI;
using Microsoft.Extensions.DependencyInjection;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;

namespace AI.Sentinel.ClaudeCode;

/// <summary>
/// Vendor-agnostic pipeline runner for hook adapters. Takes the mapped
/// <see cref="ChatMessage"/> list, runs it through AI.Sentinel prompt-only, with no inner
/// LLM call, and returns a <see cref="HookOutput"/>.
/// </summary>
/// <remarks>
/// Each detection gets its own decision. One whose action is Quarantine maps through <see cref="HookConfig"/>
/// by severity. One whose action is Alert surfaces as Warn, or as Allow when HookConfig maps its severity to
/// Allow. One whose action is Log or PassThrough gives Allow. The hook answers the most restrictive of these
/// decisions, and its reason names the detection behind it, the higher severity on a tie.
/// <para>
/// Public so that other vendor adapters (e.g. <c>AI.Sentinel.Copilot</c>)
/// can call it after doing their own payload -> messages mapping.
/// </para>
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
    /// <returns>Allow when nothing was detected, otherwise the most restrictive per-detection decision.</returns>
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

        // Build a pipeline bound to an unused inner client — a prompt-only scan
        // never invokes it, so the client shape is irrelevant. This scan returns every
        // detection with its action, so the hook decides per detection.
        var pipeline = provider.BuildSentinelPipeline(UnusedChatClient.Instance);
        var findings = await pipeline.ScanMessagesForFindingsAsync(
            messages, string.IsNullOrWhiteSpace(sessionId) ? null : new SessionId(sessionId), ct).ConfigureAwait(false);

        // A clean scan, or one refused by the rate limit, allows. Hook invocations don't
        // honor rate limits (they're not real LLM calls), so the latter is unreachable in practice.
        return Decide(findings, config);
    }

    /// <summary>
    /// The most restrictive per-detection decision, and on a tie the higher severity for the reason. Deciding per
    /// detection, rather than mapping the most restrictive action's representative, keeps an Alert, such as a
    /// compliance finding in the hook CLIs, from being lost when it co-fires with a Quarantine detection whose
    /// severity HookConfig maps to Allow.
    /// </summary>
    internal static HookOutput Decide(IReadOnlyList<ScanFinding> findings, HookConfig config)
    {
        DetectionResult? reason = null;
        var decision = HookDecision.Allow;
        foreach (var finding in findings)
        {
            if (DecisionFor(finding, config) is not { } candidate) continue;
            if (reason is null || candidate > decision
                || (candidate == decision && finding.Detection.Severity > reason.Severity))
            {
                decision = candidate;
                reason = finding.Detection;
            }
        }

        return reason is null
            ? new HookOutput { Decision = HookDecision.Allow }
            : new HookOutput { Decision = decision, Reason = $"{reason.DetectorId.Value} {reason.Severity}: {reason.Reason}" };
    }

    /// <summary>
    /// Quarantine maps through <see cref="HookConfig"/> by severity. Alert warns, but never overrides an operator who
    /// mapped its severity to Allow. Log and PassThrough allow without a reason, so they return
    /// <see langword="null"/>.
    /// </summary>
    private static HookDecision? DecisionFor(ScanFinding finding, HookConfig config)
    {
        var mapped = HookSeverityMapper.Map(finding.Detection.Severity, config);
        return finding.Action switch
        {
            SentinelAction.Quarantine => mapped,
            SentinelAction.Alert => mapped < HookDecision.Warn ? mapped : HookDecision.Warn,
            _ => null,
        };
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
