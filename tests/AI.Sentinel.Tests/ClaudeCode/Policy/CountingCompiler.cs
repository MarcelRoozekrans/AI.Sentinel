using AI.Sentinel.ClaudeCode.Policy.Rego;

namespace AI.Sentinel.Tests.ClaudeCode.Policy;

/// <summary>Counts every compilation the wrapped compiler is asked for, into a count shared with other counters, so a test
/// sees how often a policy was compiled whichever compiler the machine provides.</summary>
internal sealed class CountingCompiler(IRegoCompiler inner, Func<int> next) : IRegoCompiler
{
    public string Name => inner.Name;

    public string? Unavailable() => inner.Unavailable();

    public byte[] CompileWasm(PolicySources sources, bool restrictBuiltins)
    {
        next();
        return inner.CompileWasm(sources, restrictBuiltins);
    }
}
