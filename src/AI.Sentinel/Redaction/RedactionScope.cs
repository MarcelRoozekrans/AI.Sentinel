using System.Runtime.CompilerServices;
using AI.Sentinel.Authorization;
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
/// <para>
/// Sentinel clients stacked above one function-invoking client form a chain through <see cref="Parent"/>:
/// the model saw the innermost layer's placeholders over the outer layers' ones, so arguments are restored
/// innermost first and anything going back to the model is redacted outermost first.
/// </para>
/// </summary>
internal sealed class RedactionScope(RedactionSession session, bool restoreArguments, RedactionScope? parent = null)
{
    private const string FailedResult = "Error: AI.Sentinel could not redact this tool call, so the request was stopped.";

    private static readonly AsyncLocal<RedactionScope?> CurrentScope = new();
    private static readonly ConditionalWeakTable<FunctionInvokingChatClient, object> Hooked = new();
    private static readonly object HookLock = new();

    private int _failed;

    public RedactionSession Session => session;

    /// <summary>The scope of an enclosing Sentinel call, when one is current as this one starts.</summary>
    public RedactionScope? Parent => parent;

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
        if (arguments is null || CurrentScope.Value is not { } scope)
        {
            return arguments;
        }

        var comparer = ComparerOf(arguments);
        var restored = scope.RestoreArguments(new AIFunctionArguments(arguments, comparer), comparer);
        return restored ?? arguments;
    }

    /// <summary>
    /// The placeholders a detector must not flag as a value: those <paramref name="own"/> minted, those every
    /// enclosing Sentinel call in the <paramref name="parent"/> chain minted, and <paramref name="extra"/>.
    /// Null when there are none to exempt, so a call that redacts nothing exempts nothing.
    /// </summary>
    public static IReadOnlySet<string>? ExemptPlaceholders(
        RedactionSession? own, RedactionScope? parent, IReadOnlySet<string>? extra = null)
    {
        if (own is null && parent is null && extra is null)
        {
            return null;
        }

        var exempt = new HashSet<string>(StringComparer.Ordinal);
        if (own is not null)
        {
            exempt.UnionWith(own.MintedTokens);
        }
        for (var s = parent; s is not null; s = s.Parent)
        {
            exempt.UnionWith(s.Session.MintedTokens);
        }
        if (extra is not null)
        {
            exempt.UnionWith(extra);
        }
        return exempt;
    }

    private static IEqualityComparer<string> ComparerOf(IDictionary<string, object?>? arguments) =>
        (arguments as Dictionary<string, object?>)?.Comparer ?? StringComparer.Ordinal;

    // Innermost first: each layer turns its own placeholders back into what the layer above handed it.
    // Returns null when no layer restores.
    private AIFunctionArguments? RestoreArguments(AIFunctionArguments arguments, IEqualityComparer<string> comparer)
    {
        AIFunctionArguments? restored = null;
        for (var s = this; s is not null; s = s.Parent)
        {
            if (s.RestoresArguments)
            {
                restored = s.Session.Restore(restored ?? arguments, comparer);
            }
        }
        return restored;
    }

    private bool RestoresArguments => restoreArguments;

    // Outermost first, mirroring how the request itself was redacted on its way down.
    private List<RedactionScope> OutermostFirst()
    {
        var chain = new List<RedactionScope>();
        for (var s = this; s is not null; s = s.Parent)
        {
            chain.Add(s);
        }
        chain.Reverse();
        return chain;
    }

    private object? RedactResult(object? result)
    {
        foreach (var s in OutermostFirst())
        {
            result = s.Session.RedactResult(result);
        }
        return result;
    }

    private string RedactText(string text)
    {
        foreach (var s in OutermostFirst())
        {
            text = s.Session.Redact(text);
        }
        return text;
    }

    // The tool ran with real values, so its message may hold one, and FunctionInvokingChatClient puts the
    // message into the history it sends to the model when IncludeDetailedErrors is set, or rethrows the
    // exception to the caller after too many errors. Only the message is redacted: the inner exception keeps
    // the original, with its values, for the application, and anything that renders the whole exception,
    // such as ToString or a logger, includes it. Null when the message cannot be redacted.
    private RedactedToolInvocationException? TryRedact(Exception ex)
    {
        try
        {
            return new RedactedToolInvocationException(RedactText(ex.Message), ex);
        }
        catch (Exception redactionFailure) when (redactionFailure is not OperationCanceledException)
        {
            return null;
        }
    }

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

        try
        {
            var comparer = ComparerOf(context.CallContent.Arguments);
            if (scope.RestoreArguments(context.Arguments, comparer) is { } restored)
            {
                context.Arguments = restored;
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return scope.Fail(context);
        }

        object? result;
        try
        {
            result = await next(context, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (ToolCallAuthorizationException)
        {
            // A denial names the caller, tool and policy, never an argument value.
            throw;
        }
        catch (Exception ex)
        {
            if (scope.TryRedact(ex) is { } redacted)
            {
                throw redacted;
            }
            return scope.Fail(context);
        }

        try
        {
            return scope.RedactResult(result);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return scope.Fail(context);
        }
    }

    // Fails closed without letting anything unredacted through: the tool result becomes a fixed message,
    // the function-invoking client stops before calling the model again, and every Sentinel call in the
    // chain fails.
    private string Fail(FunctionInvocationContext context)
    {
        for (var s = this; s is not null; s = s.Parent)
        {
            Volatile.Write(ref s._failed, 1);
        }
        context.Terminate = true;
        return FailedResult;
    }
}
