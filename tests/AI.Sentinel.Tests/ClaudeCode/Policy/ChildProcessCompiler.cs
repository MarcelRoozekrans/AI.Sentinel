using AI.Sentinel.ClaudeCode.Policy.Rego;

namespace AI.Sentinel.Tests.ClaudeCode.Policy;

/// <summary>
/// The compiler the hooks use, a child process of <c>sentinel-hook</c> started with <see cref="PolicyCompileCommand.Verb"/>,
/// run here as <c>dotnet AI.Sentinel.ClaudeCode.Cli.dll</c>. The Go runtime of the interop compiler so never loads into the
/// test host, where it crashes tests that run after it. It can be made to leave
/// out the capabilities document.
/// </summary>
internal sealed class ChildProcessCompiler(bool unrestricted = false) : IRegoCompiler
{
    private readonly ChildProcessRegoCompiler _inner = new(RegoPolicyTestSupport.DotnetHost(), [RegoPolicyTestSupport.HookAssembly], InteropRegoCompiler.Unavailable());

    public bool Unrestricted => unrestricted;

    public string Name => _inner.Name;

    public string? Unavailable() => _inner.Unavailable();

    public byte[] CompileWasm(PolicySources sources, bool restrictBuiltins)
    {
        return _inner.CompileWasm(sources, restrictBuiltins && !unrestricted);
    }
}
