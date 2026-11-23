using System.Formats.Tar;
using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using OpaDotNet.Compilation.Abstractions;
using OpaDotNet.Compilation.Interop;

namespace RegoAot;

/// <summary>Turns the Rego bundles of a set into one WebAssembly module.</summary>
internal interface ICompiler
{
    string Name { get; }

    string? Unavailable();

    /// <summary>Compiles all bundles to one wasm module. A capabilities document restricts the builtins that may be used.</summary>
    byte[] CompileWasm(BundleSet set, string? capabilitiesJson = null);
}

internal sealed class OpaCliCompiler : ICompiler
{
    public string Name => "opa-cli";

    public string? Unavailable() => OpaTool.Unavailable();

    public byte[] CompileWasm(BundleSet set, string? capabilitiesJson = null)
    {
        var tmp = Path.Combine(Path.GetTempPath(), "regoaot-build-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tmp);
        try
        {
            var bundle = Path.Combine(tmp, "bundle.tar.gz");
            var args = new List<string> { "build", "-t", "wasm", "-e", BundleSet.Entrypoint, "-o", bundle };
            if (capabilitiesJson is not null)
            {
                var caps = Path.Combine(tmp, "capabilities.json");
                File.WriteAllText(caps, capabilitiesJson);
                args.Add("--capabilities");
                args.Add(caps);
            }

            args.Add(set.Root);
            var (exit, output, err) = OpaTool.Run(args);
            if (exit != 0)
            {
                // opa build prints its compile errors on stdout.
                throw new RegoCompileException((output + err).Trim());
            }

            return ReadWasm(File.OpenRead(bundle));
        }
        finally
        {
            Directory.Delete(tmp, recursive: true);
        }
    }

    internal static byte[] ReadWasm(Stream tarGz)
    {
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
}

/// <summary>
/// The interop compiler of OpaDotNet: the OPA compiler as a native library, called in process. No opa
/// binary has to be installed. The package ships the library for linux-x64 and win-x64 only.
/// </summary>
internal sealed class InteropCompiler : ICompiler
{
    public string Name => "interop";

    public string? Unavailable() =>
        RuntimeInformation.ProcessArchitecture == Architecture.X64 && (OperatingSystem.IsLinux() || OperatingSystem.IsWindows())
            ? null
            : $"the package has no native library for {RuntimeInformation.OSDescription} {RuntimeInformation.ProcessArchitecture}";

    public byte[] CompileWasm(BundleSet set, string? capabilitiesJson = null)
    {
        var compiler = new RegoInteropCompiler(NullLogger<RegoInteropCompiler>.Instance);
        var parameters = new CompilationParameters
        {
            IsBundle = true,
            Entrypoints = [BundleSet.Entrypoint],
        };
        if (capabilitiesJson is not null)
        {
            parameters.CapabilitiesBytes = Encoding.UTF8.GetBytes(capabilitiesJson);
        }

        try
        {
            using var bundle = compiler.Compile(set.Root, parameters, CancellationToken.None).GetAwaiter().GetResult();
            return OpaCliCompiler.ReadWasm(bundle);
        }
        catch (RegoCompilationException e)
        {
            throw new RegoCompileException(e.Message);
        }
    }
}

internal sealed class RegoCompileException(string message) : Exception(message);

/// <summary>Builtins that reach outside the process: a bundle using one is refused when it is validated.</summary>
internal static class OutsideBuiltins
{
    public static readonly string[] Names = ["http.send", "net.lookup_ip_addr", "opa.runtime"];

    /// <summary>
    /// The capabilities document of OPA v1.22.4 without the builtins above, read from capabilities.json.
    /// It was made with: opa capabilities --current, then dropping the three builtins from the list.
    /// A compiler given this document reports every use of a dropped builtin as an undefined function.
    /// </summary>
    public static string Capabilities() => File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "capabilities.json"));

    public static List<string> NamedIn(string message) => Names.Where(n => message.Contains(n, StringComparison.Ordinal)).ToList();

    /// <summary>
    /// A lexical scan for engines that have no capabilities document: the names that occur in the sources
    /// outside comments and string literals. It over-refuses (a name in a rule head would count) and cannot
    /// see anything a compiler would resolve, so a compiler with capabilities is the better check.
    /// </summary>
    public static List<string> Scan(BundleSet set)
    {
        var found = new List<string>();
        foreach (var file in set.Files)
        {
            var code = StripCommentsAndStrings(File.ReadAllText(Path.Combine(set.Root, file)));
            foreach (var name in Names)
            {
                for (var at = code.IndexOf(name, StringComparison.Ordinal); at >= 0; at = code.IndexOf(name, at + 1, StringComparison.Ordinal))
                {
                    var before = at == 0 ? ' ' : code[at - 1];
                    var after = at + name.Length < code.Length ? code[at + name.Length] : ' ';
                    if (!IsNameChar(before) && !IsNameChar(after) && !found.Contains(name, StringComparer.Ordinal))
                    {
                        found.Add(name);
                    }
                }
            }
        }

        return found;
    }

    private static bool IsNameChar(char c) => char.IsLetterOrDigit(c) || c is '_' or '.';

    private static string StripCommentsAndStrings(string source)
    {
        var sb = new StringBuilder(source.Length);
        for (var i = 0; i < source.Length; i++)
        {
            var c = source[i];
            if (c == '#')
            {
                while (i < source.Length && source[i] != '\n')
                {
                    i++;
                }

                sb.Append('\n');
            }
            else if (c == '"')
            {
                for (i++; i < source.Length && source[i] != '"'; i++)
                {
                    i += source[i] == '\\' ? 1 : 0;
                }

                sb.Append("\"\"");
            }
            else if (c == '`')
            {
                i = source.IndexOf('`', i + 1);
                i = i < 0 ? source.Length : i;
                sb.Append("``");
            }
            else
            {
                sb.Append(c);
            }
        }

        return sb.ToString();
    }
}
