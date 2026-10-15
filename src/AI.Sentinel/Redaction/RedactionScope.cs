using System.Runtime.CompilerServices;
using AI.Sentinel.Tools;
using Microsoft.Extensions.AI;

namespace AI.Sentinel.Redaction;

/// <summary>
/// The redaction state of one outer Sentinel call, visible to the tool invocations that call makes.
/// <para>
/// When a <c>FunctionInvokingChatClient</c> sits below Sentinel, the model's tool calls run inside it, after
/// the model replied and before Sentinel sees anything. Every such client below a Sentinel pipeline gets
/// exactly ONE invocation hook, keyed by that instance alone. The hook holds no state: it reads the scope
/// of whichever Sentinel call is current in this execution context, so concurrent requests and different
/// Sentinel clients sharing one function-invoking client never share a session, and no second hook stacks.
/// With no scope the hook passes through.
/// </para>
/// </summary>
internal sealed class RedactionScope(RedactionSession session, bool restoreArguments)
{
    private const string FailedResult = "Error: AI.Sentinel could not redact this tool call, so the request was stopped.";

    private static readonly AsyncLocal<RedactionScope?> CurrentScope = new();
    private static readonly ConditionalWeakTable<FunctionInvokingChatClient, object> Hooked = new();
    private static readonly object HookLock = new();

    private int _failed;

    public RedactionSession Session => session;

    /// <summary>True when a tool invocation could not be redacted; the call it belongs to must fail.</summary>
    public bool Failed => Volatile.Read(ref _failed) != 0;

    /// <summary>
    /// The scope of the Sentinel call this execution context belongs to. Sentinel sets it inside its own
    /// async method, so the value flows into the inner clients and never back out to its caller.
    /// </summary>
    public static RedactionScope? Current
    {
        get => CurrentScope.Value;
        set => CurrentScope.Value = value;
    }

    /// <summary>Installs the hook on the function-invoking client below <paramref name="inner"/>, once per client.</summary>
    public static void InstallToolHook(IChatClient inner)
    {
        ArgumentNullException.ThrowIfNull(inner);
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

            if (ToolInvocationInterception.TryChainInvoker(invoking, HookAsync, ToolInterceptorStage.RewriteArguments))
            {
                Hooked.Add(invoking, HookLock);
            }
        }
    }

    /// <summary>
    /// The arguments a tool would receive for a call the model made in this scope, for a check that judges
    /// a call before it runs. Returns <paramref name="arguments"/> unchanged outside a scope.
    /// </summary>
    public static IDictionary<string, object?>? AsInvoked(IDictionary<string, object?>? arguments)
    {
        if (arguments is null || CurrentScope.Value is not { } scope || !scope.RestoresArguments)
        {
            return arguments;
        }

        var comparer = ComparerOf(arguments);
        return scope.Session.Restore(new AIFunctionArguments(arguments, comparer), comparer);
    }

    private bool RestoresArguments => restoreArguments;

    private static IEqualityComparer<string> ComparerOf(IDictionary<string, object?>? arguments) =>
        (arguments as Dictionary<string, object?>)?.Comparer ?? StringComparer.Ordinal;

    // Rewrite stage: runs before every gate, so authorization judges the arguments the function receives.
    private static async ValueTask<object?> HookAsync(
        FunctionInvocationContext context, ToolInvocationInterception.ToolInvoker next, CancellationToken ct)
    {
        if (CurrentScope.Value is not { } scope)
        {
            return await next(context, ct).ConfigureAwait(false);
        }

        // The tool body and anything it calls run outside this request's redaction: a nested agent's tool
        // calls must never resolve this request's placeholders.
        CurrentScope.Value = null;

        if (scope.RestoresArguments)
        {
            try
            {
                context.Arguments = scope.Session.Restore(context.Arguments, ComparerOf(context.CallContent.Arguments));
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                return scope.Fail(context);
            }
        }

        var result = await next(context, ct).ConfigureAwait(false);
        try
        {
            return scope.Session.RedactResult(result);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return scope.Fail(context);
        }
    }

    // Fails closed without letting anything unredacted through: the tool result becomes a fixed message,
    // the function-invoking client stops before calling the model again, and Sentinel fails the call.
    private string Fail(FunctionInvocationContext context)
    {
        Volatile.Write(ref _failed, 1);
        context.Terminate = true;
        return FailedResult;
    }
}
