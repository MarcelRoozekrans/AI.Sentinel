using System.Text.Json;
using AI.Sentinel.Approvals;
using AI.Sentinel.Audit;
using AI.Sentinel.Authorization;
using AI.Sentinel.Domain;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.DependencyInjection;
using ZeroAlloc.Authorization;

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
    private readonly IAuditForwarder[] _forwarders;

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
        _forwarders = AuditForwarding.Snapshot(provider.GetServices<IAuditForwarder>());
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
    /// <remarks>
    /// On <see cref="HookEvent.PostToolUse"/> with <see cref="HookConfig.RedactToolResults"/> on, a redacted result gives
    /// Allow, and the caller must deliver <see cref="HookOutput.UpdatedToolOutput"/> instead of the original output. A
    /// Block also carries <see cref="HookOutput.UpdatedToolOutput"/>: the withheld body that replaces the output.
    /// </remarks>
    public async Task<HookOutput> HandleAsync(HookEvent evt, HookInput input, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(input);

        if (evt == HookEvent.PreToolUse && await AuthorizeAsync(input, ct).ConfigureAwait(false) is { } unauthorized)
        {
            return unauthorized;
        }

        // A redaction placeholder written into a file or a command would replace the real value there. Denied
        // without an audit entry: nothing was detected, and the call never runs.
        if (evt == HookEvent.PreToolUse && _config.RedactToolResults
            && PlaceholderGuard.Check(input.ToolName, input.ToolInput ?? default, PlaceholderGuard.ClaudeCodeTools) is { } denied)
        {
            return denied;
        }

        return await ScanAsync(evt, input, ct).ConfigureAwait(false);
    }

    /// <summary>Asks the <see cref="IToolCallGuard"/>, when one is registered, whether the tool call may run. A Block
    /// with the denial or approval receipt when it may not, audited as AUTHZ-DENY; otherwise <see langword="null"/>.</summary>
    private async Task<HookOutput?> AuthorizeAsync(HookInput input, CancellationToken ct)
    {
        if (_guard is null || string.IsNullOrEmpty(input.ToolName))
        {
            return null;
        }

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
                        reason: $"approval required (requestId={r.RequestId})",
                        policyCode: SentinelDenyCodes.ApprovalRequired);
                    await _audit.AppendAndForwardAsync(approvalEntry, _forwarders, ct).ConfigureAwait(false);
                }

                return new HookOutput { Decision = HookDecision.Block, Reason = ApprovalReceipt.Format(input.ToolName, r) };
            }

            var deny = decision as AuthorizationDecision.DenyDecision;  // defensive `??` below — see AuthorizationChatClient.AuditDenyAsync
            var policyName = deny?.PolicyName ?? "?";
            var denyReason = deny?.Reason ?? "?";
            var denyCode = deny?.Code ?? SentinelDenyCodes.PolicyDenied;

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
                    reason: denyReason,
                    policyCode: denyCode);
                await _audit.AppendAndForwardAsync(entry, _forwarders, ct).ConfigureAwait(false);
            }

            var reason = $"Authorization denied [{denyCode}] by policy '{policyName}': {denyReason}";
            return new HookOutput { Decision = HookDecision.Block, Reason = reason };
        }

        return null;
    }

    private async Task<HookOutput> ScanAsync(HookEvent evt, HookInput input, CancellationToken ct)
    {
        // A tool result can be replaced before the model sees it, so it is redacted rather than judged as it is.
        // Every other event, and a result with redaction switched off, keeps the 3.0 scan and its fallback.
        if (evt == HookEvent.PostToolUse && _config.RedactToolResults && input.ToolResponse is { } toolResponse
            && toolResponse.ValueKind != JsonValueKind.Undefined)
        {
            return await HookPipelineRunner.RunToolResultAsync(
                _provider, _config, [ToolCallMessage(input)], toolResponse, input.SessionId, ct).ConfigureAwait(false);
        }

        var messages = BuildMessages(evt, input);
        var output = await HookPipelineRunner.RunAsync(
            _provider, _config, messages, input.SessionId, evt == HookEvent.PostToolUse ? 1 : 0, ct).ConfigureAwait(false);

        // A blocked tool result is withheld also when redaction is off: the tool already ran, so replacing its output
        // is the only way to keep it from the model.
        return evt == HookEvent.PostToolUse && output.Decision == HookDecision.Block
            ? output with { UpdatedToolOutput = HookPipelineRunner.WithheldOutput(input.ToolResponse ?? default, output.Reason) }
            : output;
    }

    private static ChatMessage ToolCallMessage(HookInput input) =>
        new(ChatRole.User, $"tool:{input.ToolName} input:{input.ToolInput?.GetRawText() ?? ""}");

    private static IReadOnlyList<ChatMessage> BuildMessages(HookEvent evt, HookInput input) => evt switch
    {
        HookEvent.UserPromptSubmit => [new ChatMessage(ChatRole.User, input.Prompt ?? "")],
        HookEvent.PreToolUse => [ToolCallMessage(input)],
        HookEvent.PostToolUse =>
        [
            ToolCallMessage(input),
            new ChatMessage(ChatRole.Assistant,
                input.ToolResponse?.GetRawText() ?? ""),
        ],
        _ => throw new ArgumentOutOfRangeException(nameof(evt)),
    };
}
