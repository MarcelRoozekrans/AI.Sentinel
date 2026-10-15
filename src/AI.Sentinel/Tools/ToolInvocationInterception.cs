using Microsoft.Extensions.AI;

namespace AI.Sentinel.Tools;

/// <summary>
/// Hooks the point where <c>FunctionInvokingChatClient</c> runs a model-requested tool, which no
/// message-level check can see: the call arrives in a model response and executes before the next
/// request is built.
/// </summary>
internal static class ToolInvocationInterception
{
    /// <summary>
    /// Runs on every invocation of a tool the model asked for. <paramref name="inner"/> is the real
    /// function; the interceptor decides whether, and with which arguments, to call it.
    /// </summary>
    internal delegate ValueTask<object?> ToolInterceptor(AIFunction inner, AIFunctionArguments args, CancellationToken ct);

    /// <summary>
    /// Returns a clone of <paramref name="options"/> in which every <see cref="AIFunction"/> in
    /// <see cref="ChatOptions.Tools"/> is wrapped so that <paramref name="interceptor"/> runs on
    /// each invocation. Other <see cref="AITool"/>s are kept as they are, and a function already
    /// wrapped for the same interceptor is not wrapped again. The caller's options are not mutated.
    /// </summary>
    public static ChatOptions? WrapTools(ChatOptions? options, ToolInterceptor interceptor)
    {
        ArgumentNullException.ThrowIfNull(interceptor);
        if (options?.Tools is not { Count: > 0 } tools)
        {
            return options;
        }

        var wrapped = new List<AITool>(tools.Count);
        foreach (var tool in tools)
        {
            wrapped.Add(tool is AIFunction fn && !(fn is InterceptingAIFunction mine && mine.Interceptor.Equals(interceptor))
                ? new InterceptingAIFunction(fn, interceptor)
                : tool);
        }

        var clone = options.Clone();
        clone.Tools = wrapped;
        return clone;
    }

    private sealed class InterceptingAIFunction(AIFunction inner, ToolInterceptor interceptor) : DelegatingAIFunction(inner)
    {
        public ToolInterceptor Interceptor => interceptor;

        protected override ValueTask<object?> InvokeCoreAsync(AIFunctionArguments arguments, CancellationToken cancellationToken)
            => interceptor(InnerFunction, arguments, cancellationToken);
    }
}
