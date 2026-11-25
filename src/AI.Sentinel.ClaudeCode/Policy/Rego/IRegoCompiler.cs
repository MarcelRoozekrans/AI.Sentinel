namespace AI.Sentinel.ClaudeCode.Policy.Rego;

/// <summary>Turns the Rego of a <see cref="PolicySources"/> into one WebAssembly module.</summary>
internal interface IRegoCompiler
{
    string Name { get; }

    /// <summary>Why this compiler cannot run here, or <see langword="null"/> when it can.</summary>
    string? Unavailable();

    /// <summary>Compiles every file to one module with the entrypoint <see cref="PolicySources.Entrypoint"/>. With
    /// <paramref name="restrictBuiltins"/> the compiler is given the capabilities without <see cref="OutsideBuiltins"/>
    /// and refuses a policy that uses one.</summary>
    /// <exception cref="RegoCompileException">The policy does not compile, or uses a builtin that is refused.</exception>
    byte[] CompileWasm(PolicySources sources, bool restrictBuiltins);
}
