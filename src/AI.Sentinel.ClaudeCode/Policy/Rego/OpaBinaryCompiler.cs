using System.Diagnostics;
using System.Formats.Tar;
using System.IO.Compression;
using System.Text;

namespace AI.Sentinel.ClaudeCode.Policy.Rego;

/// <summary>The <c>opa</c> binary as a separate process: <c>opa build -t wasm</c>. It runs wherever OPA does, and has to be on
/// the PATH. It is the compiler where the interop one has no native library.</summary>
internal sealed class OpaBinaryCompiler : IRegoCompiler
{
    private readonly string? _path;
    private readonly TimeSpan _timeout;

    public OpaBinaryCompiler() : this(Find(), ChildProcessRegoCompiler.DefaultTimeout)
    {
    }

    /// <param name="path">The <c>opa</c> executable, or <see langword="null"/> when there is none.</param>
    /// <param name="timeout">How long a build may take before the process is stopped.</param>
    internal OpaBinaryCompiler(string? path, TimeSpan timeout)
    {
        _path = path;
        _timeout = timeout;
    }

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
        var output = process.StandardOutput.ReadToEndAsync();
        var clock = Stopwatch.StartNew();
        if (!process.WaitForExit(_timeout))
        {
            process.Kill(entireProcessTree: true);
            process.WaitForExit();
            throw new TimeoutException($"opa did not finish within {_timeout.TotalSeconds:0} s and was stopped");
        }

        if (process.ExitCode != 0)
        {
            // A child that opa left running can hold its output pipes open, so what opa printed is read within the same
            // deadline, never until the pipes close. opa build prints its compile errors on stdout.
            var remaining = _timeout - clock.Elapsed;
            if (!Task.WaitAll([output, error], remaining > TimeSpan.Zero ? remaining : TimeSpan.Zero))
            {
                throw new TimeoutException($"opa failed and its output did not close within {_timeout.TotalSeconds:0} s");
            }

            throw RegoCompileException.From(output.GetAwaiter().GetResult() + error.GetAwaiter().GetResult());
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
