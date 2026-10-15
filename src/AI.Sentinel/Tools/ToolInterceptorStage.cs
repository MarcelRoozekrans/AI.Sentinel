namespace AI.Sentinel.Tools;

/// <summary>Where an interceptor runs relative to the others on the same function-invoking client.</summary>
internal enum ToolInterceptorStage
{
    /// <summary>Decides whether the call may run, judging the arguments the function will receive.</summary>
    Gate,

    /// <summary>
    /// Rewrites the arguments into what the function will receive. Every rewrite interceptor runs before
    /// every gate, whatever order the clients were built in, so a gate never judges arguments that are
    /// still about to change.
    /// </summary>
    RewriteArguments,
}
