using System.Runtime.CompilerServices;
using System.Text.Json;
using AI.Sentinel.Audit;
using AI.Sentinel.Domain;
using Microsoft.Extensions.AI;

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
    IAuditStore? audit) : IChatClient
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
                if (content is not FunctionCallContent fnCall)
                {
                    continue;
                }

                var argsJson = JsonSerializer.SerializeToElement(fnCall.Arguments);
                var decision = await guard.AuthorizeAsync(caller, fnCall.Name, argsJson, ct).ConfigureAwait(false);
                if (decision.Allowed)
                {
                    continue;
                }

                if (audit is not null)
                {
                    var entry = AuditEntryAuthorizationExtensions.AuthorizationDeny(
                        sender: new AgentId(string.IsNullOrWhiteSpace(caller.Id) ? "anonymous" : caller.Id),
                        receiver: new AgentId(fnCall.Name),
                        session: SessionId.New(),
                        callerId: caller.Id,
                        roles: caller.Roles,
                        toolName: fnCall.Name,
                        policyName: decision.PolicyName ?? "?",
                        reason: decision.Reason ?? "?");
                    await audit.AppendAsync(entry, ct).ConfigureAwait(false);
                }

                throw new ToolCallAuthorizationException(decision);
            }
        }
    }

    public object? GetService(Type serviceType, object? serviceKey = null)
    {
        ArgumentNullException.ThrowIfNull(serviceType);
        return serviceType == typeof(IToolCallGuard) ? guard : inner.GetService(serviceType, serviceKey);
    }

    public void Dispose() => inner.Dispose();
}
