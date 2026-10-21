using System.Text.Json;
using AI.Sentinel.Approvals;
using AI.Sentinel.Audit;
using AI.Sentinel.Authorization;
using AI.Sentinel.ClaudeCode;
using AI.Sentinel.Domain;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.DependencyInjection;
using ZeroAlloc.Authorization;

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
    private readonly IAuditForwarder[] _forwarders;

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
        _forwarders = AuditForwarding.Snapshot(provider.GetServices<IAuditForwarder>());
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
        => (await HandleForCliAsync(evt, input, ct).ConfigureAwait(false)).Output;

    /// <summary>
    /// Handles a single hook event, returning the decision and, for <see cref="CopilotHookEvent.UserPromptTransformed"/>,
    /// the prompt the model should receive instead.
    /// </summary>
    /// <remarks>
    /// <list type="bullet">
    /// <item>On <see cref="CopilotHookEvent.PostToolUse"/> a <c>toolResult</c> holding <c>textResultForLlm</c> is redacted;
    /// <see cref="HookOutput.UpdatedToolOutput"/> carries the redacted result. A Block withholds the result, also with
    /// redaction off: <see cref="HookOutput.UpdatedToolOutput"/> is then the withheld text as a JSON string.</item>
    /// <item>On <see cref="CopilotHookEvent.UserPromptTransformed"/> the transformed prompt, or the prompt when there is
    /// none, is redacted, and a Block withholds it, also with redaction off.</item>
    /// <item>Every other event keeps the scan and its fallback.</item>
    /// </list>
    /// </remarks>
    internal async Task<CopilotHookResult> HandleForCliAsync(
        CopilotHookEvent evt,
        CopilotHookInput input,
        CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(input);

        if (evt == CopilotHookEvent.PreToolUse && await AuthorizeAsync(input, ct).ConfigureAwait(false) is { } unauthorized)
        {
            return new CopilotHookResult(unauthorized, null);
        }

        // A redaction placeholder written into a file or a command would replace the real value there. Denied
        // without an audit entry: nothing was detected, and the call never runs. toolArgs sent as a JSON string is
        // parsed first, so the guard walks the same shape either way.
        if (evt == CopilotHookEvent.PreToolUse && _config.RedactToolResults
            && PlaceholderGuard.Check(input.ToolName, input.GuardToolArgs(default), PlaceholderGuard.CopilotTools) is { } denied)
        {
            return new CopilotHookResult(denied, null);
        }

        return evt switch
        {
            CopilotHookEvent.PostToolUse => new CopilotHookResult(await ScanToolResultAsync(input, ct).ConfigureAwait(false), null),
            CopilotHookEvent.UserPromptTransformed => await ScanTransformedPromptAsync(input, ct).ConfigureAwait(false),
            _ => new CopilotHookResult(
                await HookPipelineRunner.RunAsync(_provider, _config.ToSharedConfig(), BuildMessages(evt, input), input.SessionId, ct).ConfigureAwait(false),
                null),
        };
    }

    /// <summary>Redacts a <c>toolResult</c> that holds <c>textResultForLlm</c>, the only shape Copilot's
    /// <c>modifiedResult</c> can carry back; any other result, and every result with redaction off, keeps the scan
    /// and its fallback. A Block withholds the result either way.</summary>
    private async Task<HookOutput> ScanToolResultAsync(CopilotHookInput input, CancellationToken ct)
    {
        var shared = _config.ToSharedConfig();
        var output = _config.RedactToolResults && input.ToolResult is { } toolResult && CopilotToolResult.TextForLlm(toolResult) is not null
            ? await HookPipelineRunner.RunToolResultAsync(
                _provider, shared, [ToolCallMessage(input)], toolResult, input.SessionId, ct).ConfigureAwait(false)
            : await HookPipelineRunner.RunAsync(
                _provider, shared, BuildMessages(CopilotHookEvent.PostToolUse, input), input.SessionId, ct).ConfigureAwait(false);

        // The tool already ran, so replacing its result is the only way to keep it from the model. modifiedResult
        // carries text only, so the withheld body is the withheld text itself.
        return output.Decision == HookDecision.Block
            ? output with { UpdatedToolOutput = HookPipelineRunner.JsonString(HookPipelineRunner.WithheldPrefix + output.Reason) }
            : output;
    }

    /// <summary>Redacts the transformed prompt, or the prompt when Copilot sent no transformed one. With redaction off
    /// the prompt is scanned as it is, and a Block still withholds it: exit code 2 is only a warning on this event.</summary>
    private async Task<CopilotHookResult> ScanTransformedPromptAsync(CopilotHookInput input, CancellationToken ct)
    {
        var shared = _config.ToSharedConfig();
        var prompt = input.TransformedPrompt ?? input.Prompt ?? "";
        if (_config.RedactToolResults)
        {
            var (redacted, rewritten) = await HookPipelineRunner.RunPromptAsync(
                _provider, shared, prompt, input.SessionId, ct).ConfigureAwait(false);
            return new CopilotHookResult(redacted, rewritten);
        }

        var output = await HookPipelineRunner.RunAsync(
            _provider, shared, [new ChatMessage(ChatRole.User, prompt)], input.SessionId, ct).ConfigureAwait(false);
        return new CopilotHookResult(
            output, output.Decision == HookDecision.Block ? HookPipelineRunner.WithheldPrefix + output.Reason : null);
    }

    /// <summary>Asks the <see cref="IToolCallGuard"/>, when one is registered, whether the tool call may run. A Block
    /// with the denial or approval receipt when it may not, audited as AUTHZ-DENY; otherwise <see langword="null"/>.</summary>
    private async Task<HookOutput?> AuthorizeAsync(CopilotHookInput input, CancellationToken ct)
    {
        if (_guard is null || string.IsNullOrEmpty(input.ToolName))
        {
            return null;
        }

        var caller = _config.CallerContextProvider?.Invoke(input) ?? AnonymousSecurityContext.Instance;
        var args = input.GuardToolArgs(EmptyJsonObject);
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

    private static ChatMessage ToolCallMessage(CopilotHookInput input) =>
        new(ChatRole.User, $"tool:{input.ToolName} input:{input.ToolArgsText()}");

    private static IReadOnlyList<ChatMessage> BuildMessages(
        CopilotHookEvent evt,
        CopilotHookInput input) => evt switch
        {
            CopilotHookEvent.UserPromptSubmitted => [new ChatMessage(ChatRole.User, input.Prompt ?? "")],
            CopilotHookEvent.PreToolUse => [ToolCallMessage(input)],
            CopilotHookEvent.PostToolUse =>
            [
                ToolCallMessage(input),
                new ChatMessage(ChatRole.Assistant, input.ToolResultText()),
            ],
            _ => throw new ArgumentOutOfRangeException(nameof(evt)),
        };
}
