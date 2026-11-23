using AI.Sentinel.ClaudeCode.Policy.Rego;

namespace AI.Sentinel.Tests.ClaudeCode.Policy;

/// <summary>
/// The compiler the hooks use, a child process of <c>sentinel-hook</c> started with <see cref="PolicyCompileCommand.Verb"/>,
/// run here as <c>dotnet AI.Sentinel.ClaudeCode.Cli.dll</c>. The Go runtime of the interop compiler so never loads into the
/// test host, where it crashes tests that run after it. It counts how often it was asked to compile, and can be made to leave
/// out the capabilities document.
/// </summary>
internal sealed class ChildProcessCompiler(bool unrestricted = false) : IRegoCompiler
{
    private readonly ChildProcessRegoCompiler _inner = new(RegoPolicyTestSupport.DotnetHost(), [RegoPolicyTestSupport.HookAssembly], InteropRegoCompiler.Unavailable());

    public int Compiles { get; private set; }

    public string Name => _inner.Name;

    public string? Unavailable() => _inner.Unavailable();

    public byte[] CompileWasm(PolicySources sources, bool restrictBuiltins)
    {
        Compiles++;
        return _inner.CompileWasm(sources, restrictBuiltins && !unrestricted);
    }
}
