using System.Runtime.InteropServices;
#if INTEROP_COMPILER
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using OpaDotNet.Compilation.Abstractions;
using OpaDotNet.Compilation.Interop;
#endif

namespace AI.Sentinel.ClaudeCode.Policy.Rego;

/// <summary>
/// The OPA compiler as a native library, called in process: no <c>opa</c> binary has to be installed. The package ships the
/// library for linux-x64 and win-x64 only, and is not referenced for any other runtime identifier.
/// </summary>
internal sealed class InteropRegoCompiler : IRegoCompiler
{
    public string Name => "interop";

#if INTEROP_COMPILER
    public string? Unavailable() =>
        RuntimeInformation.ProcessArchitecture == Architecture.X64 && (OperatingSystem.IsLinux() || OperatingSystem.IsWindows())
            ? null
            : $"the OpaDotNet interop compiler has no native library for {RuntimeInformation.OSDescription} {RuntimeInformation.ProcessArchitecture}";

    public byte[] CompileWasm(PolicySources sources, bool restrictBuiltins)
    {
        ArgumentNullException.ThrowIfNull(sources);
        using var work = new TempFolder();
        SourceFolder.Write(sources, work.Path);
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
            using var bundle = compiler.Compile(work.Path, parameters, CancellationToken.None).GetAwaiter().GetResult();
            return OpaBinaryCompiler.ReadWasm(bundle);
        }
        catch (RegoCompilationException e)
        {
            throw RegoCompileException.From(e.Message);
        }
    }
#else
    public string? Unavailable() =>
        $"the OpaDotNet interop compiler has no native library for {RuntimeInformation.OSDescription} {RuntimeInformation.ProcessArchitecture}, so this build does not include it";

    public byte[] CompileWasm(PolicySources sources, bool restrictBuiltins) =>
        throw new PlatformNotSupportedException(Unavailable());
#endif
}
