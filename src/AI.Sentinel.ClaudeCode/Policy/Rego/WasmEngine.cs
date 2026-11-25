using Wasmtime;

namespace AI.Sentinel.ClaudeCode.Policy.Rego;

/// <summary>
/// The Wasmtime engine every policy module runs in, and its settings. The native code of a module only loads into an engine
/// of the same Wasmtime version and settings, so <see cref="Settings"/> and <see cref="Version"/> are part of the cache key.
/// </summary>
internal static class WasmEngine
{
    /// <summary>The settings of <see cref="Create"/>: Wasmtime's defaults. Change this when <see cref="Create"/> changes.</summary>
    public const string Settings = "default";

    /// <summary>The version of the Wasmtime .NET assembly, and with it the native library it was built for.</summary>
    public static string Version { get; } = typeof(Engine).Assembly.GetName().Version?.ToString() ?? "unknown";

    private static readonly Lazy<Engine> Shared = new(() => new Engine());

    /// <summary>
    /// The one engine of the process, never disposed. Wasmtime installs its signal handlers when the first engine is made and
    /// puts the earlier ones back when the last engine is dropped, which breaks any handler another native library, such as the
    /// Go runtime inside the interop compiler, installed in between. One engine for the life of the process avoids that, and a
    /// hook process loads one policy anyway.
    /// </summary>
    public static Engine Create() => Shared.Value;

    /// <summary>The native code of <paramref name="wasm"/>, to be loaded with <see cref="WasmEvaluator.FromNative"/>.</summary>
    public static byte[] Precompile(byte[] wasm)
    {
        ArgumentNullException.ThrowIfNull(wasm);
        using var module = Module.FromBytes(Create(), "policy", wasm);
        return module.Serialize();
    }
}
