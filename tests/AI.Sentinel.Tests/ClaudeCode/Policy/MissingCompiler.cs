using AI.Sentinel.ClaudeCode.Policy.Rego;

namespace AI.Sentinel.Tests.ClaudeCode.Policy;

/// <summary>A compiler that cannot run here, as the interop one cannot on macOS or an ARM machine.</summary>
internal sealed class MissingCompiler : IRegoCompiler
{
    public string Name => "missing";

    public string? Unavailable() => "no compiler on this machine";

    public byte[] CompileWasm(PolicySources sources, bool restrictBuiltins) => throw new InvalidOperationException("never called");
}
