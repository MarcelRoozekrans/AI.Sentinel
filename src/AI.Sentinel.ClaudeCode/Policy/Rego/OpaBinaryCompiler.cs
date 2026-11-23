using System.Diagnostics;
using System.Formats.Tar;
using System.IO.Compression;
using System.Text;

namespace AI.Sentinel.ClaudeCode.Policy.Rego;

/// <summary>The <c>opa</c> binary as a separate process: <c>opa build -t wasm</c>. It runs wherever OPA does, and has to be on
/// the PATH. It is the compiler where the interop one has no native library.</summary>
internal sealed class OpaBinaryCompiler : IRegoCompiler
{
    private readonly string? _path = Find();

    public string Name => "opa";

    public string? Unavailable() => _path is null ? "no opa binary on the PATH" : null;

    public byte[] CompileWasm(PolicySources sources, bool restrictBuiltins)
    {
        ArgumentNullException.ThrowIfNull(sources);
        var opa = _path ?? throw new InvalidOperationException(Unavailable());
        using var work = new TempFolder();
        var root = Path.Combine(work.Path, "policy");
        SourceFolder.Write(sources, root);
        var bundle = Path.Combine(work.Path, "bundle.tar.gz");
        var psi = new ProcessStartInfo(opa)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };
        foreach (var arg in new[] { "build", "-t", "wasm", "-e", PolicySources.Entrypoint, "-o", bundle })
        {
            psi.ArgumentList.Add(arg);
        }

        if (restrictBuiltins)
        {
            var capabilities = Path.Combine(work.Path, "capabilities.json");
            File.WriteAllText(capabilities, OutsideBuiltins.Capabilities());
            psi.ArgumentList.Add("--capabilities");
            psi.ArgumentList.Add(capabilities);
        }

        psi.ArgumentList.Add(root);
        using var process = Process.Start(psi) ?? throw new InvalidOperationException("opa did not start");
        var error = process.StandardError.ReadToEndAsync();
        var output = process.StandardOutput.ReadToEnd();
        process.WaitForExit();
        if (process.ExitCode != 0)
        {
            // opa build prints its compile errors on stdout.
            throw RegoCompileException.From(output + error.GetAwaiter().GetResult());
        }

        using var file = File.OpenRead(bundle);
        return ReadWasm(file);
    }

    /// <summary>The <c>policy.wasm</c> inside the bundle tarball that <c>opa build</c> and the interop compiler write.</summary>
    internal static byte[] ReadWasm(Stream tarGz)
    {
        ArgumentNullException.ThrowIfNull(tarGz);
        using var gz = new GZipStream(tarGz, CompressionMode.Decompress);
        using var tar = new TarReader(gz);
        while (tar.GetNextEntry() is { } entry)
        {
            if (entry.Name.EndsWith("policy.wasm", StringComparison.Ordinal) && entry.DataStream is { } data)
            {
                using var ms = new MemoryStream();
                data.CopyTo(ms);
                return ms.ToArray();
            }
        }

        throw new RegoCompileException("the bundle holds no policy.wasm");
    }

    private static string? Find()
    {
        var exe = OperatingSystem.IsWindows() ? "opa.exe" : "opa";
        foreach (var dir in (Environment.GetEnvironmentVariable("PATH") ?? string.Empty).Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            var candidate = Path.Combine(dir, exe);
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        return null;
    }
}
