using System.Formats.Tar;
using System.IO.Compression;
using System.Text.Json.Nodes;

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
            var (exit, _, err) = OpaTool.Run(args);
            if (exit != 0)
            {
                throw new RegoCompileException(err.Trim());
            }

            return ReadWasm(File.OpenRead(bundle));
        }
        finally
        {
            Directory.Delete(tmp, recursive: true);
        }
    }

    private static byte[] ReadWasm(Stream tarGz)
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

internal sealed class RegoCompileException(string message) : Exception(message);

/// <summary>Builtins that reach outside the process: a bundle using one is refused when it is validated.</summary>
internal static class OutsideBuiltins
{
    public static readonly string[] Names = ["http.send", "net.lookup_ip_addr", "opa.runtime"];

    /// <summary>The current capabilities of OPA without the builtins that reach outside.</summary>
    public static string Capabilities()
    {
        var (exit, json, err) = OpaTool.Run(["capabilities", "--current"]);
        if (exit != 0)
        {
            throw new InvalidOperationException(err);
        }

        var doc = JsonNode.Parse(json)!.AsObject();
        var builtins = doc["builtins"]!.AsArray();
        for (var i = builtins.Count - 1; i >= 0; i--)
        {
            if (Array.IndexOf(Names, builtins[i]!["name"]!.GetValue<string>()) >= 0)
            {
                builtins.RemoveAt(i);
            }
        }

        return doc.ToJsonString();
    }
}
