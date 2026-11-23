using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using OpaDotNet.Compilation.Abstractions;
using OpaDotNet.Compilation.Interop;

namespace AI.Sentinel.ClaudeCode.Policy.Rego;

/// <summary>
/// The OPA compiler as a native library: no <c>opa</c> binary has to be installed. The library is a Go runtime, and a crash in
/// it ends the process that loaded it, so only the child process of <see cref="PolicyCompileCommand"/> calls this; a hook
/// reaches it through <see cref="ChildProcessRegoCompiler"/>. The package ships the library for linux-x64 and win-x64 only.
/// The code is in every build, so the library is built once for every runtime identifier, and <see cref="Unavailable()"/>
/// decides at run time whether this process can load it.
/// </summary>
internal static class InteropRegoCompiler
{
    /// <summary>Why the compiler cannot run here, or <see langword="null"/> when it can.</summary>
    public static string? Unavailable() =>
        Unavailable(RuntimeInformation.RuntimeIdentifier, RuntimeInformation.ProcessArchitecture, OperatingSystem.IsLinux(), OperatingSystem.IsWindows());

    /// <summary>Why the compiler cannot run on this platform, or <see langword="null"/> when it can. musl is left out: the
    /// linux-x64 library is built against glibc, and the RID graph still copies it into a linux-musl-x64 build.</summary>
    internal static string? Unavailable(string runtimeIdentifier, Architecture architecture, bool isLinux, bool isWindows) =>
        architecture == Architecture.X64
        && (isWindows || (isLinux && !runtimeIdentifier.Contains("musl", StringComparison.OrdinalIgnoreCase)))
            ? null
            : $"the OpaDotNet interop compiler has no native library for {runtimeIdentifier}";

    /// <summary>Compiles the Rego files of <paramref name="root"/>, as <see cref="SourceFolder"/> writes them, to one module
    /// with the entrypoint <see cref="PolicySources.Entrypoint"/>.</summary>
    /// <exception cref="RegoCompileException">The policy does not compile, or uses a builtin that is refused.</exception>
    public static byte[] CompileFolder(string root, bool restrictBuiltins)
    {
        ArgumentException.ThrowIfNullOrEmpty(root);
        var compiler = new RegoInteropCompiler(NullLogger<RegoInteropCompiler>.Instance);
        var parameters = new CompilationParameters
        {
            IsBundle = true,
            Entrypoints = [PolicySources.Entrypoint],
        };
        if (restrictBuiltins)
        {
            parameters.CapabilitiesBytes = Encoding.UTF8.GetBytes(OutsideBuiltins.Capabilities());
        }

        try
        {
            using var bundle = compiler.Compile(root, parameters, CancellationToken.None).GetAwaiter().GetResult();
            return OpaBinaryCompiler.ReadWasm(bundle);
        }
        catch (RegoCompilationException e)
        {
            throw RegoCompileException.From(e.Message);
        }
    }
}
