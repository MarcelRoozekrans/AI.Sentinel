using AI.Sentinel.Approvals;
using AI.Sentinel.Audit;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.DependencyInjection;
using ZeroAlloc.Authorization;

namespace AI.Sentinel.Authorization;

/// <summary>Extension methods on <see cref="ChatClientBuilder"/> for tool-call authorization.</summary>
public static class AuthorizationChatClientBuilderExtensions
{
    /// <summary>
    /// Wraps the chain with an authorization gate that runs <see cref="IToolCallGuard"/> on every
    /// <see cref="FunctionCallContent"/> in the outgoing messages. Deny decisions throw
    /// <see cref="ToolCallAuthorizationException"/> and (when an <see cref="IAuditStore"/> is
    /// registered) emit an <c>AUTHZ-DENY</c> audit entry.
    /// </summary>
    /// <param name="builder">The chat client builder to extend.</param>
    /// <returns>The same <see cref="ChatClientBuilder"/> instance, to support fluent chaining.</returns>
    public static ChatClientBuilder UseToolCallAuthorization(this ChatClientBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        return builder.Use((inner, sp) =>
        {
            var guard = sp.GetRequiredService<IToolCallGuard>();
            var audit = sp.GetService<IAuditStore>();
            var approvalStore = sp.GetService<IApprovalStore>();
            Func<ISecurityContext> callerProvider = () =>
                sp.GetService<ISecurityContext>() ?? AnonymousSecurityContext.Instance;
            return new AuthorizationChatClient(inner, guard, callerProvider, audit, approvalStore);
        });
    }
}
