using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Text.Json;
using AI.Sentinel.Approvals;
using AI.Sentinel.Audit;
using AI.Sentinel.Domain;
using AI.Sentinel.Tools;
using Microsoft.Extensions.AI;
using ZeroAlloc.Authorization;

namespace AI.Sentinel.Authorization;

/// <summary>
/// Delegating <see cref="IChatClient"/> that authorizes outgoing tool calls before forwarding
/// the request to the inner client. Every <see cref="FunctionCallContent"/> in the supplied
/// messages is evaluated by the configured <see cref="IToolCallGuard"/>; a deny decision throws
/// a <see cref="ToolCallAuthorizationException"/> and (when an <see cref="IAuditStore"/> is
/// available) appends an <c>AUTHZ-DENY</c> audit entry first.
/// <para>
/// Tool calls the MODEL makes are authorized too, in whichever order this client sits relative to
/// <c>FunctionInvokingChatClient</c>. Outside it, the guard is chained into that client's function
/// invoker, so it runs immediately before each invocation of any tool. Inside it, the calls in the model's response are checked
/// before they are returned, so the function-invoking client never sees a denied call.
/// </para>
/// </summary>
internal sealed class AuthorizationChatClient : IChatClient
{
    private readonly IChatClient inner;
    private readonly IToolCallGuard guard;
    private readonly Func<ISecurityContext> callerProvider;
    private readonly IAuditStore? audit;
    private readonly IApprovalStore? approvalStore;
    private readonly IAuditForwarder[] _forwarders;

    // Outcome of every call the invocation hook decided in the CURRENT non-streaming request, by call id:
    // null when allowed, the denial otherwise. FunctionInvokingChatClient swallows a throwing function and
    // reports it to the model as a failed result, so the response check uses this to tell "we decided this
    // call" from "a result is merely present", and to surface a denial to the caller. The dictionary is
    // created per request and reached through an AsyncLocal (the hook runs inside the request's execution
    // context), so nothing is shared between requests or outlives one. Model call ids repeat across
    // conversations, so a store shared on this client would mix up callers.
    private readonly AsyncLocal<ConcurrentDictionary<string, ToolCallAuthorizationException?>?> _requestOutcomes = new();

    public AuthorizationChatClient(
        IChatClient inner,
        IToolCallGuard guard,
        Func<ISecurityContext> callerProvider,
        IAuditStore? audit,
        IApprovalStore? approvalStore = null,
        IAuditForwarder[]? forwarders = null)
    {
        this.inner = inner;
        this.guard = guard;
        this.callerProvider = callerProvider;
        this.audit = audit;
        this.approvalStore = approvalStore;
        _forwarders = forwarders ?? [];
        InstallInvocationHook();
    }

    // When a FunctionInvokingChatClient sits below this client (the "outside" order), hook the point
    // where it invokes a function. That one point covers ChatOptions.Tools and AdditionalTools alike,
    // and needs no per-request change to the caller's options. Chained once, here, on the pipeline's own
    // instance. With no such client below (the "inside" order) there is nothing to hook: calls are
    // checked in the model response instead.
    private void InstallInvocationHook()
        => ToolInvocationInterception.TryChainInvoker(inner, async (context, next, ct) =>
        {
            var caller = callerProvider() ?? AnonymousSecurityContext.Instance;
            var outcomes = _requestOutcomes.Value;   // null while streaming: nothing is recorded
            try
            {
                await AuthorizeFunctionCallAsync(
                    new FunctionCallContent(context.CallContent.CallId, context.Function.Name, context.Arguments), caller, ct).ConfigureAwait(false);
            }
            catch (ToolCallAuthorizationException denial)
            {
                if (outcomes is not null)
                {
                    outcomes[context.CallContent.CallId] = denial;
                }

                throw;
            }

            if (outcomes is not null)
            {
                outcomes[context.CallContent.CallId] = null;
            }

            return await next(context, ct).ConfigureAwait(false);
        });

    public async Task<ChatResponse> GetResponseAsync(
        IEnumerable<ChatMessage> messages,
        ChatOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        await AuthorizeFunctionCallsAsync(messages, cancellationToken).ConfigureAwait(false);
        var outcomes = new ConcurrentDictionary<string, ToolCallAuthorizationException?>(StringComparer.Ordinal);
        _requestOutcomes.Value = outcomes;
        var response = await inner.GetResponseAsync(messages, options, cancellationToken).ConfigureAwait(false);
        await AuthorizePendingCallsAsync(response.Messages, outcomes, cancellationToken).ConfigureAwait(false);
        return response;
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
            // Streaming outside FunctionInvokingChatClient evaluates an allowed call twice: here, as it is
            // streamed, and again in the invocation hook. The guard is a pure decision, so this is only cost.
            await AuthorizeUpdateAsync(update, ct).ConfigureAwait(false);
            yield return update;
        }
    }

    private static HashSet<string> CollectAnsweredCallIds(IEnumerable<ChatMessage> messages)
    {
        var answered = new HashSet<string>(StringComparer.Ordinal);
        foreach (var msg in messages)
        {
            foreach (var content in msg.Contents)
            {
                if (content is FunctionResultContent result)
                {
                    answered.Add(result.CallId);
                }
            }
        }

        return answered;
    }

    // A call that already has a result in the same list is history: it was authorized, or denied and
    // audited, when it ran. Re-checking it would audit a second time and wedge the conversation after a
    // denial. Calls without a result are checked.
    private async ValueTask AuthorizeFunctionCallsAsync(IEnumerable<ChatMessage> messages, CancellationToken ct)
    {
        var messageList = messages as IList<ChatMessage> ?? [.. messages];
        var answered = CollectAnsweredCallIds(messageList);
        var caller = callerProvider() ?? AnonymousSecurityContext.Instance;
        foreach (var msg in messageList)
        {
            foreach (var content in msg.Contents)
            {
                if (content is FunctionCallContent fnCall && !answered.Contains(fnCall.CallId))
                {
                    await AuthorizeFunctionCallAsync(fnCall, caller, ct).ConfigureAwait(false);
                }
            }
        }
    }

    // Calls in a model response. A call with a result alongside it is not re-evaluated, but only because
    // the invocation hook decided that very call id (a result alone proves nothing): an allowed call is
    // skipped, a denied one is rethrown to the caller without a second audit entry.
    private async ValueTask AuthorizePendingCallsAsync(
        IList<ChatMessage> responseMessages, ConcurrentDictionary<string, ToolCallAuthorizationException?> outcomes, CancellationToken ct)
    {
        var answered = CollectAnsweredCallIds(responseMessages);

        var caller = callerProvider() ?? AnonymousSecurityContext.Instance;
        foreach (var msg in responseMessages)
        {
            foreach (var content in msg.Contents)
            {
                if (content is not FunctionCallContent fnCall)
                {
                    continue;
                }

                if (answered.Contains(fnCall.CallId) && outcomes.TryGetValue(fnCall.CallId, out var denial))
                {
                    if (denial is not null)
                    {
                        throw denial;
                    }

                    continue;
                }

                await AuthorizeFunctionCallAsync(fnCall, caller, ct).ConfigureAwait(false);
            }
        }
    }

    private async ValueTask AuthorizeUpdateAsync(ChatResponseUpdate update, CancellationToken ct)
    {
        var caller = callerProvider() ?? AnonymousSecurityContext.Instance;
        foreach (var content in update.Contents)
        {
            if (content is FunctionCallContent fnCall)
            {
                await AuthorizeFunctionCallAsync(fnCall, caller, ct).ConfigureAwait(false);
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

        // Defensive null-coalesce on every deny field below: `deny` is non-null when `decision`
        // IS a DenyDecision, but the closed hierarchy could be extended in the future (this method
        // only runs on the deny path today, but the pattern keeps the audit-write resilient against
        // a hypothetical 4th decision subtype). DenyDecision.Code defaults to PolicyDenied so
        // `deny.Code` is never null when deny is non-null — the `??` here defends against the
        // `decision is not DenyDecision` case, not against a null Code.
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
        await audit.AppendAndForwardAsync(entry, _forwarders, ct).ConfigureAwait(false);
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
