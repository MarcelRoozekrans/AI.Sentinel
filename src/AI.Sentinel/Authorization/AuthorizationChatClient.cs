using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Text.Json;
using AI.Sentinel.Approvals;
using AI.Sentinel.Audit;
using AI.Sentinel.Domain;
using Microsoft.Extensions.AI;
using ZeroAlloc.Authorization;

namespace AI.Sentinel.Authorization;

/// <summary>
/// Delegating <see cref="IChatClient"/> that authorizes outgoing tool calls before forwarding
/// the request to the inner client. Every <see cref="FunctionCallContent"/> in the supplied
/// messages is evaluated by the configured <see cref="IToolCallGuard"/>; a deny decision throws
/// a <see cref="ToolCallAuthorizationException"/> and (when an <see cref="IAuditStore"/> is
/// available) appends an <c>AUTHZ-DENY</c> audit entry first.
/// </summary>
internal sealed class AuthorizationChatClient(
    IChatClient inner,
    IToolCallGuard guard,
    Func<ISecurityContext> callerProvider,
    IAuditStore? audit,
    IApprovalStore? approvalStore = null) : IChatClient
{
    public async Task<ChatResponse> GetResponseAsync(
        IEnumerable<ChatMessage> messages,
        ChatOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        await AuthorizeFunctionCallsAsync(messages, cancellationToken).ConfigureAwait(false);
        return await inner.GetResponseAsync(messages, options, cancellationToken).ConfigureAwait(false);
    }

    public IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(
        IEnumerable<ChatMessage> messages,
        ChatOptions? options = null,
        CancellationToken cancellationToken = default)
        => StreamCoreAsync(messages, options, cancellationToken);

    private async IAsyncEnumerable<ChatResponseUpdate> StreamCoreAsync(
        IEnumerable<ChatMessage> messages,
        ChatOptions? options,
        [EnumeratorCancellation] CancellationToken ct)
    {
        await AuthorizeFunctionCallsAsync(messages, ct).ConfigureAwait(false);
        await foreach (var update in inner.GetStreamingResponseAsync(messages, options, ct).ConfigureAwait(false))
        {
            yield return update;
        }
    }

    private async ValueTask AuthorizeFunctionCallsAsync(IEnumerable<ChatMessage> messages, CancellationToken ct)
    {
        var caller = callerProvider() ?? AnonymousSecurityContext.Instance;
        foreach (var msg in messages)
        {
            foreach (var content in msg.Contents)
            {
                if (content is FunctionCallContent fnCall)
                {
                    await AuthorizeFunctionCallAsync(fnCall, caller, ct).ConfigureAwait(false);
                }
            }
        }
    }

    private const int MaxApprovalIterations = 5;

    private async ValueTask AuthorizeFunctionCallAsync(
        FunctionCallContent fnCall, ISecurityContext caller, CancellationToken ct)
    {
        // Tool arguments are IDictionary<string, object?> with arbitrary value shapes
        // (primitives, nested objects, arrays). Reflection-based serialisation is required;
        // a JsonSerializerContext can't statically describe `object?`. AuthorizationChatClient
        // is opt-in (only wired when the consumer calls AddAuthorizationGuard) so AOT/trimming
        // consumers must avoid this delegating client. The CLI hooks (sentinel-hook, etc.)
        // never wire it, so the AOT publish pipeline never reaches this code path at runtime.
        JsonElement argsJson = SerializeArgumentsForAuthorization(fnCall.Arguments);

        AuthorizationDecision decision = AuthorizationDecision.Allow;   // satisfies definite-assignment
        for (var iteration = 0; iteration < MaxApprovalIterations; iteration++)
        {
            decision = await guard.AuthorizeAsync(caller, fnCall.Name, argsJson, ct).ConfigureAwait(false);

            if (decision.Allowed)
            {
                return;
            }

            if (decision is AuthorizationDecision.RequireApprovalDecision r && approvalStore is not null)
            {
                // Long-lived host: wait for the approval to settle, then re-query the guard so any
                // bindings registered AFTER the approval binding (which the guard short-circuited
                // past on the previous call) get a chance to evaluate.
                var settled = await approvalStore.WaitForDecisionAsync(r.RequestId, r.WaitTimeout, ct).ConfigureAwait(false);
                if (settled is ApprovalState.Active)
                {
                    continue;   // re-query guard — subsequent bindings may still gate
                }

                // Pending (timeout) or Denied — fold into a Deny so the existing audit + throw flow
                // runs. Folding happens BEFORE audit so the audit captures the actual denial reason,
                // not the original "approval pending" reason.
                var reason = settled switch
                {
                    ApprovalState.Denied d => $"Approval denied: {d.Reason}",
                    _                      => $"Approval timed out after {r.WaitTimeout.TotalSeconds:F0}s (request {r.RequestId})",
                };
                decision = AuthorizationDecision.Deny(r.PolicyName, reason);
            }

            // Deny path (or RequireApproval with no store) — audit + throw.
            await AuditDenyAsync(fnCall, caller, decision, ct).ConfigureAwait(false);
            throw new ToolCallAuthorizationException(decision);
        }

        // Defensive — should never reach here unless guard keeps returning RequireApproval
        // for >MaxApprovalIterations distinct bindings (implausible).
        throw new ToolCallAuthorizationException(AuthorizationDecision.Deny(
            "approval-loop",
            $"Approval iteration limit ({MaxApprovalIterations}) exceeded for tool {fnCall.Name}"));
    }

    private async ValueTask AuditDenyAsync(
        FunctionCallContent fnCall, ISecurityContext caller, AuthorizationDecision decision, CancellationToken ct)
    {
        if (audit is null)
        {
            return;
        }

        var deny = decision as AuthorizationDecision.DenyDecision;
        var entry = AuditEntryAuthorizationExtensions.AuthorizationDeny(
            sender: new AgentId(string.IsNullOrWhiteSpace(caller.Id) ? "anonymous" : caller.Id),
            receiver: new AgentId(fnCall.Name),
            session: SessionId.New(),
            callerId: caller.Id,
            roles: caller.Roles,
            toolName: fnCall.Name,
            policyName: deny?.PolicyName ?? "?",
            reason: deny?.Reason ?? "?",
            policyCode: deny?.Code ?? SentinelDenyCodes.PolicyDenied);
        await audit.AppendAsync(entry, ct).ConfigureAwait(false);
    }

    public object? GetService(Type serviceType, object? serviceKey = null)
    {
        ArgumentNullException.ThrowIfNull(serviceType);
        return serviceType == typeof(IToolCallGuard) ? guard : inner.GetService(serviceType, serviceKey);
    }

    public void Dispose() => inner.Dispose();

    [UnconditionalSuppressMessage("Trimming", "IL2026:Members annotated with 'RequiresUnreferencedCodeAttribute' require dynamic access otherwise can break functionality when trimming application code", Justification = SerializerJustification)]
    [UnconditionalSuppressMessage("AotAnalysis", "IL3050:Avoid calling members marked with 'RequiresDynamicCodeAttribute' when publishing as native AOT", Justification = SerializerJustification)]
    private static JsonElement SerializeArgumentsForAuthorization(IDictionary<string, object?>? arguments)
        => JsonSerializer.SerializeToElement(arguments);

    private const string SerializerJustification =
        "Tool argument values are IDictionary<string, object?> with arbitrary shapes; " +
        "JsonSerializerContext source-gen can't statically describe `object?`. " +
        "AuthorizationChatClient is opt-in (only wired by AddAuthorizationGuard), and the CLI " +
        "hooks that AOT-publish never reach this path. Native AOT consumers wiring this client " +
        "must accept the dynamic-code requirement.";
}
