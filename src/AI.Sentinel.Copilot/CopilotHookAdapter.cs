using System.Text.Json;
using AI.Sentinel.Approvals;
using AI.Sentinel.Audit;
using AI.Sentinel.Authorization;
using AI.Sentinel.ClaudeCode;
using AI.Sentinel.Domain;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.DependencyInjection;

namespace AI.Sentinel.Copilot;

/// <summary>
/// Adapter that maps GitHub Copilot hook payloads to AI.Sentinel scans. On
/// <see cref="CopilotHookEvent.PreToolUse"/>, the configured <see cref="IToolCallGuard"/>
/// (resolved from the supplied <see cref="IServiceProvider"/>) authorizes the call
/// before the detection pipeline runs.
/// </summary>
public sealed class CopilotHookAdapter
{
    // Static cache: parsed once at type init, kept alive for the process. Avoids per-call JsonDocument allocation.
    private static readonly JsonElement EmptyJsonObject = JsonDocument.Parse("{}").RootElement;

    private readonly IServiceProvider _provider;
    private readonly CopilotHookConfig _config;
    private readonly IToolCallGuard? _guard;
    private readonly IAuditStore? _audit;

    /// <summary>
    /// Builds an adapter that resolves <see cref="IToolCallGuard"/> and <see cref="IAuditStore"/>
    /// from <paramref name="provider"/> when present (so deny decisions audit automatically).
    /// </summary>
    /// <param name="provider">Service provider that owns the AI.Sentinel registrations.</param>
    /// <param name="config">Optional configuration; defaults to <see cref="CopilotHookConfig"/>'s defaults.</param>
    public CopilotHookAdapter(IServiceProvider provider, CopilotHookConfig? config = null)
        : this(provider, config, provider is null ? null : provider.GetService<IToolCallGuard>(), provider is null ? null : provider.GetService<IAuditStore>())
    {
    }

    private CopilotHookAdapter(IServiceProvider provider, CopilotHookConfig? config, IToolCallGuard? guard, IAuditStore? audit)
    {
        ArgumentNullException.ThrowIfNull(provider);
        _provider = provider;
        _config = config ?? new CopilotHookConfig();
        _guard = guard;
        _audit = audit;
    }

    /// <summary>
    /// Test-only factory that bypasses DI by injecting the guard directly. The detection
    /// pipeline still runs through <paramref name="provider"/>; pass a provider configured
    /// with <c>AddAISentinel</c> when detection coverage matters in the test.
    /// </summary>
    internal static CopilotHookAdapter CreateForTests(IServiceProvider provider, CopilotHookConfig? config, IToolCallGuard guard)
    {
        ArgumentNullException.ThrowIfNull(provider);
        ArgumentNullException.ThrowIfNull(guard);
        return new CopilotHookAdapter(provider, config, guard, provider.GetService<IAuditStore>());
    }

    /// <summary>Handles a single hook event, returning the decision the Copilot CLI should honour.</summary>
    public async Task<HookOutput> HandleAsync(
        CopilotHookEvent evt,
        CopilotHookInput input,
        CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(input);

        if (evt == CopilotHookEvent.PreToolUse && _guard is not null && !string.IsNullOrEmpty(input.ToolName))
        {
            var caller = _config.CallerContextProvider?.Invoke(input) ?? AnonymousSecurityContext.Instance;
            var args = input.ToolInput ?? EmptyJsonObject;
            var decision = await _guard.AuthorizeAsync(caller, input.ToolName, args, ct).ConfigureAwait(false);
            if (!decision.Allowed)
            {
                // RequireApproval: surface the receipt so the operator can find and approve the
                // pending request out of band, then retry. Audit as AUTHZ-DENY with the request id
                // so log readers can correlate Sentinel decisions with PIM activations.
                if (decision is AuthorizationDecision.RequireApprovalDecision r)
                {
                    if (_audit is not null)
                    {
                        var approvalEntry = AuditEntryAuthorizationExtensions.AuthorizationDeny(
                            sender: new AgentId(string.IsNullOrWhiteSpace(caller.Id) ? "anonymous" : caller.Id),
                            receiver: new AgentId(input.ToolName),
                            session: new SessionId(string.IsNullOrWhiteSpace(input.SessionId) ? Guid.NewGuid().ToString("N") : input.SessionId),
                            callerId: caller.Id,
                            roles: caller.Roles,
                            toolName: input.ToolName,
                            policyName: r.PolicyName,
                            reason: $"approval required (requestId={r.RequestId})");
                        await _audit.AppendAsync(approvalEntry, ct).ConfigureAwait(false);
                    }

                    return new HookOutput(HookDecision.Block, ApprovalReceipt.Format(input.ToolName, r));
                }

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
        return await HookPipelineRunner.RunAsync(_provider, _config.ToSharedConfig(), messages, ct).ConfigureAwait(false);
    }

    private static IReadOnlyList<ChatMessage> BuildMessages(
        CopilotHookEvent evt,
        CopilotHookInput input) => evt switch
    {
        CopilotHookEvent.UserPromptSubmitted => [new ChatMessage(ChatRole.User, input.Prompt ?? "")],
        CopilotHookEvent.PreToolUse => [new ChatMessage(ChatRole.User,
            $"tool:{input.ToolName} input:{input.ToolInput?.GetRawText() ?? ""}")],
        CopilotHookEvent.PostToolUse =>
        [
            new ChatMessage(ChatRole.User,
                $"tool:{input.ToolName} input:{input.ToolInput?.GetRawText() ?? ""}"),
            new ChatMessage(ChatRole.Assistant,
                input.ToolResponse?.GetRawText() ?? ""),
        ],
        _ => throw new ArgumentOutOfRangeException(nameof(evt)),
    };
}
