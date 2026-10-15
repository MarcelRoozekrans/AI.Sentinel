using System.Runtime.CompilerServices;
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

    private static readonly ConditionalWeakTable<FunctionInvokingChatClient, Chain> Chains = new();
#if NET9_0_OR_GREATER
    private static readonly System.Threading.Lock ChainLock = new();
#else
    private static readonly object ChainLock = new();
#endif

    // The interceptors installed on one function-invoking client, by stage, in the order they were chained.
    private sealed class Chain(Func<FunctionInvocationContext, CancellationToken, ValueTask<object?>>? previous)
    {
        public Func<FunctionInvocationContext, CancellationToken, ValueTask<object?>>? Previous { get; } = previous;
        public List<ToolInterceptor> Rewriters { get; } = new();
        public List<ToolInterceptor> Gates { get; } = new();
        public Func<FunctionInvocationContext, CancellationToken, ValueTask<object?>>? Installed { get; set; }
    }

    /// <summary>
    /// Chains <paramref name="interceptor"/> onto the <see cref="FunctionInvokingChatClient"/> found below
    /// <paramref name="inner"/>, around any <see cref="FunctionInvokingChatClient.FunctionInvoker"/> already
    /// set (which is never overwritten). Rewrite interceptors run before gates; within one stage, interceptors
    /// chained later run first. Returns false, and does nothing, when there is no such client below
    /// <paramref name="inner"/>.
    /// </summary>
    public static bool TryChainInvoker(
        IChatClient inner, ToolInterceptor interceptor, ToolInterceptorStage stage = ToolInterceptorStage.Gate)
    {
        ArgumentNullException.ThrowIfNull(inner);
        ArgumentNullException.ThrowIfNull(interceptor);
        if (inner.GetService(typeof(FunctionInvokingChatClient)) is not FunctionInvokingChatClient invoking)
        {
            return false;
        }

        lock (ChainLock)
        {
            // An invoker replaced by someone else since we installed ours is kept and wrapped by a fresh chain.
            if (!Chains.TryGetValue(invoking, out var chain) || !ReferenceEquals(invoking.FunctionInvoker, chain.Installed))
            {
                chain = new Chain(invoking.FunctionInvoker);
                Chains.AddOrUpdate(invoking, chain);
            }

            (stage == ToolInterceptorStage.RewriteArguments ? chain.Rewriters : chain.Gates).Add(interceptor);
            var invoker = Compose(chain);
            chain.Installed = invoker;
            invoking.FunctionInvoker = invoker;
        }

        return true;
    }

    private static Func<FunctionInvocationContext, CancellationToken, ValueTask<object?>> Compose(Chain chain)
    {
        var previous = chain.Previous;
        ToolInvoker next = previous is null
            ? static (context, ct) => context.Function.InvokeAsync(context.Arguments, ct)
            : (context, ct) => previous(context, ct);

        // Built from the innermost out: gates wrap the function, rewriters wrap the gates. Within a stage the
        // first chained ends up innermost, so the last chained runs first.
        next = Wrap(next, chain.Gates.ToArray());
        next = Wrap(next, chain.Rewriters.ToArray());
        var outermost = next;
        return (context, ct) => outermost(context, ct);
    }

    private static ToolInvoker Wrap(ToolInvoker next, ToolInterceptor[] interceptors)
    {
        foreach (var interceptor in interceptors)
        {
            var inner = next;
            next = (context, ct) => interceptor(context, inner, ct);
        }
        return next;
    }
}
