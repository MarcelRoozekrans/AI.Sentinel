using AI.Sentinel.ClaudeCode.Policy.Rego;

namespace AI.Sentinel.Tests.ClaudeCode.Policy;

/// <summary>Asks the wrapped compiler to leave out the capabilities document, as <see cref="ChildProcessCompiler"/> does when
/// it is unrestricted, so the <c>opa</c> fallback loads a policy that uses an outside builtin the same way.</summary>
internal sealed class RestrictionOverride(IRegoCompiler inner, bool unrestricted) : IRegoCompiler
{
    public string Name => inner.Name;

    public string? Unavailable() => inner.Unavailable();

    public byte[] CompileWasm(PolicySources sources, bool restrictBuiltins) =>
        inner.CompileWasm(sources, restrictBuiltins && !unrestricted);
}
