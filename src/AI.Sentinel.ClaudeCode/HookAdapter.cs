using System.Text.Json;
using AI.Sentinel.Audit;
using AI.Sentinel.Authorization;
using AI.Sentinel.Domain;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.DependencyInjection;

namespace AI.Sentinel.ClaudeCode;

/// <summary>
/// Adapter that maps Claude Code hook payloads to AI.Sentinel scans. On
/// <see cref="HookEvent.PreToolUse"/>, the configured <see cref="IToolCallGuard"/>
/// (resolved from the supplied <see cref="IServiceProvider"/>) authorizes the call
/// before the detection pipeline runs.
/// </summary>
public sealed class HookAdapter
{
    // Static cache: parsed once at type init, kept alive for the process. Avoids per-call JsonDocument allocation.
    private static readonly JsonElement EmptyJsonObject = JsonDocument.Parse("{}").RootElement;

    private readonly IServiceProvider _provider;
    private readonly HookConfig _config;
    private readonly IToolCallGuard? _guard;
    private readonly IAuditStore? _audit;

    /// <summary>
    /// Builds an adapter that resolves <see cref="IToolCallGuard"/> and <see cref="IAuditStore"/>
    /// from <paramref name="provider"/> when present (so deny decisions audit automatically).
    /// </summary>
    /// <param name="provider">Service provider that owns the AI.Sentinel registrations.</param>
    /// <param name="config">Optional configuration; defaults to <see cref="HookConfig"/>'s defaults.</param>
    public HookAdapter(IServiceProvider provider, HookConfig? config = null)
        : this(provider, config, provider is null ? null : provider.GetService<IToolCallGuard>(), provider is null ? null : provider.GetService<IAuditStore>())
    {
    }

    private HookAdapter(IServiceProvider provider, HookConfig? config, IToolCallGuard? guard, IAuditStore? audit)
    {
        ArgumentNullException.ThrowIfNull(provider);
        _provider = provider;
        _config = config ?? new HookConfig();
        _guard = guard;
        _audit = audit;
    }

    /// <summary>
    /// Test-only factory that bypasses DI by injecting the guard directly. The detection
    /// pipeline still runs through <paramref name="provider"/>; pass a provider configured
    /// with <c>AddAISentinel</c> when detection coverage matters in the test.
    /// </summary>
    internal static HookAdapter CreateForTests(IServiceProvider provider, HookConfig? config, IToolCallGuard guard)
    {
        ArgumentNullException.ThrowIfNull(provider);
        ArgumentNullException.ThrowIfNull(guard);
        return new HookAdapter(provider, config, guard, provider.GetService<IAuditStore>());
    }

    /// <summary>Handles a single hook event, returning the decision the Claude Code CLI should honour.</summary>
    public async Task<HookOutput> HandleAsync(HookEvent evt, HookInput input, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(input);

        if (evt == HookEvent.PreToolUse && _guard is not null && !string.IsNullOrEmpty(input.ToolName))
        {
            var caller = _config.CallerContextProvider?.Invoke(input) ?? AnonymousSecurityContext.Instance;
            var args = input.ToolInput ?? EmptyJsonObject;
            var decision = await _guard.AuthorizeAsync(caller, input.ToolName, args, ct).ConfigureAwait(false);
            if (!decision.Allowed)
            {
                var deny = decision as AuthorizationDecision.DenyDecision;
                var policyName = deny?.PolicyName ?? "?";
                var denyReason = deny?.Reason ?? "?";

                if (_audit is not null)
                {
                    var entry = AuditEntryAuthorizationExtensions.AuthorizationDeny(
                        sender: new AgentId(string.IsNullOrWhiteSpace(caller.Id) ? "anonymous" : caller.Id),
                        receiver: new AgentId(input.ToolName),
                        session: new SessionId(string.IsNullOrWhiteSpace(input.SessionId) ? Guid.NewGuid().ToString("N") : input.SessionId),
                        callerId: caller.Id,
                        roles: caller.Roles,
                        toolName: input.ToolName,
                        policyName: policyName,
                        reason: denyReason);
                    await _audit.AppendAsync(entry, ct).ConfigureAwait(false);
                }

                var reason = $"Authorization denied by policy '{policyName}': {denyReason}";
                return new HookOutput(HookDecision.Block, reason);
            }
        }

        var messages = BuildMessages(evt, input);
        return await HookPipelineRunner.RunAsync(_provider, _config, messages, ct).ConfigureAwait(false);
    }

    private static IReadOnlyList<ChatMessage> BuildMessages(HookEvent evt, HookInput input) => evt switch
    {
        HookEvent.UserPromptSubmit => [new ChatMessage(ChatRole.User, input.Prompt ?? "")],
        HookEvent.PreToolUse => [new ChatMessage(ChatRole.User,
            $"tool:{input.ToolName} input:{input.ToolInput?.GetRawText() ?? ""}")],
        HookEvent.PostToolUse =>
        [
            new ChatMessage(ChatRole.User,
                $"tool:{input.ToolName} input:{input.ToolInput?.GetRawText() ?? ""}"),
            new ChatMessage(ChatRole.Assistant,
                input.ToolResponse?.GetRawText() ?? ""),
        ],
        _ => throw new ArgumentOutOfRangeException(nameof(evt)),
    };
}
