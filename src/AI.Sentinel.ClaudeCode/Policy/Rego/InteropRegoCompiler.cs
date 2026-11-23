using System.Runtime.InteropServices;
#if INTEROP_COMPILER
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using OpaDotNet.Compilation.Abstractions;
using OpaDotNet.Compilation.Interop;
#endif

namespace AI.Sentinel.ClaudeCode.Policy.Rego;

/// <summary>
/// The OPA compiler as a native library: no <c>opa</c> binary has to be installed. The library is a Go runtime, and a crash in
/// it ends the process that loaded it, so only the child process of <see cref="PolicyCompileCommand"/> calls this; a hook
/// reaches it through <see cref="ChildProcessRegoCompiler"/>. The package ships the library for linux-x64 and win-x64 only,
/// and is not referenced for any other runtime identifier.
/// </summary>
internal static class InteropRegoCompiler
{
#if INTEROP_COMPILER
    /// <summary>Why the compiler cannot run here, or <see langword="null"/> when it can.</summary>
    public static string? Unavailable() =>
        RuntimeInformation.ProcessArchitecture == Architecture.X64 && (OperatingSystem.IsLinux() || OperatingSystem.IsWindows())
            ? null
            : $"the OpaDotNet interop compiler has no native library for {RuntimeInformation.OSDescription} {RuntimeInformation.ProcessArchitecture}";

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
#else
    /// <summary>Why the compiler cannot run here: this build leaves it out.</summary>
    public static string? Unavailable() =>
        $"the OpaDotNet interop compiler has no native library for {RuntimeInformation.OSDescription} {RuntimeInformation.ProcessArchitecture}, so this build does not include it";

    public static byte[] CompileFolder(string root, bool restrictBuiltins) =>
        throw new PlatformNotSupportedException(Unavailable());
#endif
}
