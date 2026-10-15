using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Text.Json;
using AI.Sentinel.Approvals;
using AI.Sentinel.Audit;
using AI.Sentinel.Domain;
using AI.Sentinel.Redaction;
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

    // Every FunctionInvokingChatClient below an authorization client gets exactly ONE invocation hook, keyed
    // by that instance alone. The hook holds no client state: it reads the scope of whichever authorization
    // client is handling the current request, so two clients sharing one function-invoking client (for
    // example a prebuilt pipeline wrapped per DI scope, each with its own caller) never authorize with each
    // other's caller, guard or forwarders, and a second client never stacks a second hook.
    private static readonly ConditionalWeakTable<FunctionInvokingChatClient, object> Hooked = new();
    private static readonly object HookLock = new();

    // The request this execution context belongs to. GetResponseAsync sets it for its own body; streaming
    // sets it immediately before every step into the inner client. Both run as async methods, so the value
    // never flows back out to their caller: a call made from inside a tool sees the enclosing request's
    // scope until it starts its own.
    private static readonly AsyncLocal<RequestScope?> CurrentScope = new();

    // Outcomes: every call the hook decided in this non-streaming request, by call id: null when allowed,
    // the denial otherwise. FunctionInvokingChatClient swallows a throwing function and reports it to the
    // model as a failed result, so the response check uses this to tell "we decided this call" from "a
    // result is merely present", and to surface a denial to the caller. Null while streaming, which has no
    // response check, so nothing is recorded. Created per request: model call ids repeat across
    // conversations, so nothing is shared between requests or outlives one.
    private sealed record RequestScope(
        AuthorizationChatClient Client,
        ISecurityContext Caller,
        ConcurrentDictionary<string, ToolCallAuthorizationException?>? Outcomes);

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
        InstallInvocationHook(inner);
    }

    // When a FunctionInvokingChatClient sits below this client (the "outside" order), hook the point
    // where it invokes a function. That one point covers ChatOptions.Tools and AdditionalTools alike,
    // and needs no per-request change to the caller's options. With no such client below (the "inside"
    // order) there is nothing to hook: calls are checked in the model response instead.
    private static void InstallInvocationHook(IChatClient inner)
    {
        if (inner.GetService(typeof(FunctionInvokingChatClient)) is not FunctionInvokingChatClient invoking)
        {
            return;
        }

        lock (HookLock)
        {
            if (Hooked.TryGetValue(invoking, out _))
            {
                return;
            }

            if (ToolInvocationInterception.TryChainInvoker(invoking, HookAsync))
            {
                Hooked.Add(invoking, HookLock);
            }
        }
    }

    // No scope means no authorization client is handling this call (the function-invoking client was
    // used directly, without authorization): pass through.
    private static ValueTask<object?> HookAsync(
        FunctionInvocationContext context, ToolInvocationInterception.ToolInvoker next, CancellationToken ct)
        => CurrentScope.Value is { } scope ? scope.Client.AuthorizeInvocationAsync(scope, context, next, ct) : next(context, ct);

    private async ValueTask<object?> AuthorizeInvocationAsync(
        RequestScope scope, FunctionInvocationContext context, ToolInvocationInterception.ToolInvoker next, CancellationToken ct)
    {
        var outcomes = scope.Outcomes;
        var callId = context.CallContent.CallId;
        try
        {
            await AuthorizeFunctionCallAsync(
                new FunctionCallContent(callId, context.Function.Name, context.Arguments), scope.Caller, ct).ConfigureAwait(false);
        }
        catch (ToolCallAuthorizationException denial)
        {
            if (outcomes is not null)
            {
                outcomes[callId] = denial;
            }

            throw;
        }

        // A recorded denial is never overwritten: FunctionInvokingChatClient loops several model turns in
        // one request, and a later turn may reuse the call id for an allowed tool.
        outcomes?.AddOrUpdate(callId, static _ => null, static (_, existing) => existing);
        return await next(context, ct).ConfigureAwait(false);
    }

    private ISecurityContext ResolveCaller() => callerProvider() ?? AnonymousSecurityContext.Instance;

    public async Task<ChatResponse> GetResponseAsync(
        IEnumerable<ChatMessage> messages,
        ChatOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        var caller = ResolveCaller();
        await AuthorizeFunctionCallsAsync(messages, caller, cancellationToken).ConfigureAwait(false);
        var outcomes = new ConcurrentDictionary<string, ToolCallAuthorizationException?>(StringComparer.Ordinal);
        CurrentScope.Value = new RequestScope(this, caller, outcomes);
        var response = await inner.GetResponseAsync(messages, options, cancellationToken).ConfigureAwait(false);
        await AuthorizePendingCallsAsync(response.Messages, outcomes, caller, cancellationToken).ConfigureAwait(false);
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
        var caller = ResolveCaller();
        await AuthorizeFunctionCallsAsync(messages, caller, ct).ConfigureAwait(false);
        var scope = new RequestScope(this, caller, Outcomes: null);

        // Each MoveNextAsync starts from the consumer's context, so the scope is set immediately before
        // every step into the inner client rather than once, including before an inner client that starts
        // eagerly in GetAsyncEnumerator.
        CurrentScope.Value = scope;
        var enumerator = inner.GetStreamingResponseAsync(messages, options, ct).GetAsyncEnumerator(ct);
        try
        {
            while (true)
            {
                CurrentScope.Value = scope;
                if (!await enumerator.MoveNextAsync().ConfigureAwait(false))
                {
                    break;
                }

                var update = enumerator.Current;
                // Streaming outside FunctionInvokingChatClient evaluates an allowed call twice: here, as it is
                // streamed, and again in the invocation hook. The guard is a pure decision, so this is only cost.
                await AuthorizeUpdateAsync(update, caller, ct).ConfigureAwait(false);
                yield return update;
            }
        }
        finally
        {
            await enumerator.DisposeAsync().ConfigureAwait(false);
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
    private async ValueTask AuthorizeFunctionCallsAsync(IEnumerable<ChatMessage> messages, ISecurityContext caller, CancellationToken ct)
    {
        var messageList = messages as IList<ChatMessage> ?? [.. messages];
        var answered = CollectAnsweredCallIds(messageList);
        foreach (var msg in messageList)
        {
            foreach (var content in msg.Contents)
            {
                if (content is FunctionCallContent fnCall && !answered.Contains(fnCall.CallId))
                {
                    await AuthorizeFunctionCallAsync(AsInvoked(fnCall), caller, ct).ConfigureAwait(false);
                }
            }
        }
    }

    // Calls in a model response. A call with a result alongside it is not re-evaluated, but only because
    // the invocation hook decided that very call id (a result alone proves nothing): an allowed call is
    // skipped, a denied one is rethrown to the caller without a second audit entry.
    private async ValueTask AuthorizePendingCallsAsync(
        IList<ChatMessage> responseMessages, ConcurrentDictionary<string, ToolCallAuthorizationException?> outcomes,
        ISecurityContext caller, CancellationToken ct)
    {
        var answered = CollectAnsweredCallIds(responseMessages);

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

                await AuthorizeFunctionCallAsync(AsInvoked(fnCall), caller, ct).ConfigureAwait(false);
            }
        }
    }

    private async ValueTask AuthorizeUpdateAsync(ChatResponseUpdate update, ISecurityContext caller, CancellationToken ct)
    {
        foreach (var content in update.Contents)
        {
            if (content is FunctionCallContent fnCall)
            {
                await AuthorizeFunctionCallAsync(AsInvoked(fnCall), caller, ct).ConfigureAwait(false);
            }
        }
    }

    // A call found in messages, as opposed to one at the invocation hook, may still hold redaction placeholders
    // when this client sits below Sentinel: Sentinel restores them only when the tool is invoked, or when the
    // response leaves it. The guard must judge what the tool will actually receive, so resolve them the same
    // way. The invocation hook needs no such step: Sentinel's argument rewrite always runs before this gate.
    private static FunctionCallContent AsInvoked(FunctionCallContent fnCall)
    {
        var arguments = RedactionScope.AsInvoked(fnCall.Arguments);
        return ReferenceEquals(arguments, fnCall.Arguments)
            ? fnCall
            : new FunctionCallContent(fnCall.CallId, fnCall.Name, arguments);
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
                    _ => $"Approval timed out after {r.WaitTimeout.TotalSeconds:F0}s (request {r.RequestId})",
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
