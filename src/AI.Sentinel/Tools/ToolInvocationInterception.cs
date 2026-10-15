using Microsoft.Extensions.AI;

namespace AI.Sentinel.Tools;

/// <summary>
/// Hooks the point where <c>FunctionInvokingChatClient</c> runs a tool the model asked for, which no
/// message-level check can see: the call arrives in a model response and executes before the next
/// request is built. The hook covers <c>ChatOptions.Tools</c> and <c>AdditionalTools</c> alike.
/// </summary>
internal static class ToolInvocationInterception
{
    /// <summary>Invokes the rest of the chain: the next interceptor, or the function itself.</summary>
    public delegate ValueTask<object?> ToolInvoker(FunctionInvocationContext context, CancellationToken ct);

    /// <summary>
    /// Runs around one tool invocation. It can read and replace <see cref="FunctionInvocationContext.Arguments"/>
    /// before calling <paramref name="next"/>, and read and replace the value <paramref name="next"/> returns.
    /// Throwing stops the tool from running.
    /// </summary>
    public delegate ValueTask<object?> ToolInterceptor(FunctionInvocationContext context, ToolInvoker next, CancellationToken ct);

    /// <summary>
    /// Chains <paramref name="interceptor"/> onto the <see cref="FunctionInvokingChatClient"/> found below
    /// <paramref name="inner"/>, around any <see cref="FunctionInvokingChatClient.FunctionInvoker"/> already
    /// set (which is never overwritten). Interceptors chained later run first. Returns false, and does
    /// nothing, when there is no such client below <paramref name="inner"/>.
    /// </summary>
    public static bool TryChainInvoker(IChatClient inner, ToolInterceptor interceptor)
    {
        ArgumentNullException.ThrowIfNull(inner);
        ArgumentNullException.ThrowIfNull(interceptor);
        if (inner.GetService(typeof(FunctionInvokingChatClient)) is not FunctionInvokingChatClient invoking)
        {
            return false;
        }

        var previous = invoking.FunctionInvoker;
        ToolInvoker next = previous is null
            ? (context, ct) => context.Function.InvokeAsync(context.Arguments, ct)
            : (context, ct) => previous(context, ct);
        invoking.FunctionInvoker = (context, ct) => interceptor(context, next, ct);
        return true;
    }
}
