using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Wasmtime;

namespace AI.Sentinel.ClaudeCode.Policy.Rego;

/// <summary>
/// The Rego files of one folder, compiled to one WebAssembly module and loaded into Wasmtime. The module is cached under the
/// hash of its sources, so a process that finds it loads native code and does not compile. A missing or damaged cache entry
/// is rebuilt, which takes about 40 ms with the interop compiler: the first call after a policy change pays it, and the
/// others do not. When nothing can be loaded this throws, and the caller blocks. It never answers <c>defer</c> for a policy
/// it could not run.
/// </summary>
internal sealed class RegoPolicy : IDisposable
{
    private readonly WasmEvaluator _evaluator;

    private RegoPolicy(WasmEvaluator evaluator, PolicySources sources)
    {
        _evaluator = evaluator;
        Version = sources.Version;
        Bundles = sources.Bundles;
    }

    /// <summary>The version of the policy: the start of the sha256 of its sources.</summary>
    public string Version { get; }

    /// <summary>The names of the bundles of the folder.</summary>
    public IReadOnlyList<string> Bundles { get; }

    /// <summary>Why the Wasmtime native library cannot be loaded on this platform, or <see langword="null"/>. Wasmtime .NET
    /// has libraries for linux-x64, linux-arm64, osx-x64, osx-arm64, win-x64 and win-arm64, and none for musl.</summary>
    internal static string? PlatformGap(string runtimeIdentifier)
    {
        ArgumentNullException.ThrowIfNull(runtimeIdentifier);
        return runtimeIdentifier.Contains("musl", StringComparison.Ordinal)
            ? $"a local Rego policy needs the Wasmtime library, which has no build for {runtimeIdentifier}"
            : null;
    }

    /// <summary>The compilers in the order they are tried: the in-process one, then the <c>opa</c> binary.</summary>
    internal static IReadOnlyList<IRegoCompiler> DefaultCompilers() => [new InteropRegoCompiler(), new OpaBinaryCompiler()];

    /// <summary>Loads the policy in <paramref name="folder"/>.</summary>
    /// <param name="folder">The policy folder.</param>
    /// <param name="cacheDir">Where the compiled forms are kept.</param>
    /// <param name="compilers">The compilers to try, in order; <see cref="DefaultCompilers"/> when <see langword="null"/>.</param>
    /// <exception cref="Exception">The folder cannot be read, the policy does not compile or uses a refused builtin, no compiler
    /// runs here, the cache cannot be written, or the Wasmtime library cannot be loaded. The caller blocks the call.</exception>
    public static RegoPolicy Load(string folder, string cacheDir, IReadOnlyList<IRegoCompiler>? compilers = null)
    {
        if (PlatformGap(RuntimeInformation.RuntimeIdentifier) is { } gap)
        {
            throw new PlatformNotSupportedException(gap);
        }

        var sources = PolicySources.Load(folder);
        try
        {
            return new RegoPolicy(LoadEvaluator(sources, cacheDir, compilers ?? DefaultCompilers()), sources);
        }
        catch (Exception e) when (e is DllNotFoundException or EntryPointNotFoundException or BadImageFormatException
            || e is TypeInitializationException { InnerException: DllNotFoundException or BadImageFormatException })
        {
            throw new PlatformNotSupportedException(
                $"a local Rego policy needs the Wasmtime library, which could not be loaded on {RuntimeInformation.RuntimeIdentifier}: {(e.InnerException ?? e).Message}", e);
        }
    }

    /// <summary>The policy's decision for the JSON input.</summary>
    public RegoDecision Evaluate(string inputJson) => _evaluator.Evaluate(inputJson);

    public void Dispose() => _evaluator.Dispose();

    private static WasmEvaluator LoadEvaluator(PolicySources sources, string cacheDir, IReadOnlyList<IRegoCompiler> compilers)
    {
        PolicyCache.Prepare(cacheDir);
        var wasmKey = $"{sources.Hash}-{CapabilitiesKey()}";
        var nativePath = Path.Combine(cacheDir, $"{wasmKey}-wasmtime{WasmEngine.Version}-{WasmEngine.Settings}.cwasm");
        if (PolicyCache.TryRead(nativePath) is { } cached && TryLoadNative(cached) is { } fromCache)
        {
            return fromCache;
        }

        var wasmPath = Path.Combine(cacheDir, wasmKey + ".wasm");
        var wasm = PolicyCache.TryRead(wasmPath);
        if (wasm is null)
        {
            wasm = Compile(sources, compilers);
            PolicyCache.Write(wasmPath, wasm);
        }

        var native = WasmEngine.Precompile(wasm);
        PolicyCache.Write(nativePath, native);
        return WasmEvaluator.FromNative(native);
    }

    // Native code from another Wasmtime version or other engine settings does not load: the entry is rebuilt, not trusted.
    private static WasmEvaluator? TryLoadNative(byte[] native)
    {
        try
        {
            return WasmEvaluator.FromNative(native);
        }
        catch (WasmtimeException)
        {
            return null;
        }
    }

    private static byte[] Compile(PolicySources sources, IReadOnlyList<IRegoCompiler> compilers)
    {
        var why = new List<string>();
        foreach (var compiler in compilers)
        {
            if (compiler.Unavailable() is { } unavailable)
            {
                why.Add($"{compiler.Name}: {unavailable}");
                continue;
            }

            return compiler.CompileWasm(sources, restrictBuiltins: true);
        }

        throw new InvalidOperationException(
            "the policy has to be compiled and no compiler can run here (" + string.Join("; ", why) + "). Compile it on a machine that has one, or install opa");
    }

    // The module a cache entry holds was checked against these capabilities, so a change to them invalidates it.
    private static string CapabilitiesKey() =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(OutsideBuiltins.Capabilities())))[..8];
}
