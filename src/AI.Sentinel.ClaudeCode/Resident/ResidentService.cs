using AI.Sentinel.ClaudeCode.Policy.Rego;

namespace AI.Sentinel.ClaudeCode.Resident;

/// <summary>What the resident process knows how to answer besides ping and shutdown.</summary>
internal sealed class ResidentService(string stateDirectory, IReadOnlyList<IRegoCompiler>? compilers) : IDisposable
{
    public string StateDirectory { get; } = stateDirectory;

    public IReadOnlyList<IRegoCompiler>? Compilers { get; } = compilers;

    public ResidentResponse Answer(ResidentRequest request) =>
        new() { Error = $"unknown operation '{request.Op}'" };

    public void Dispose()
    {
    }
}
