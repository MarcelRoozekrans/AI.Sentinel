using System.Formats.Tar;
using System.IO.Compression;
using AI.Sentinel.ClaudeCode.Policy.Rego;
using AI.Sentinel.Tests.Helpers;
using Xunit;

namespace AI.Sentinel.Tests.ClaudeCode.Policy;

[Collection("NonParallel")]
public class OpaBinaryCompilerTests
{
    private static MemoryStream Bundle(params (string Name, byte[] Data)[] entries)
    {
        var tar = new MemoryStream();
        using (var writer = new TarWriter(tar, leaveOpen: true))
        {
            foreach (var (name, data) in entries)
            {
                writer.WriteEntry(new PaxTarEntry(TarEntryType.RegularFile, name) { DataStream = new MemoryStream(data) });
            }
        }

        tar.Position = 0;
        var gz = new MemoryStream();
        using (var zip = new GZipStream(gz, CompressionLevel.Fastest, leaveOpen: true))
        {
            tar.CopyTo(zip);
        }

        gz.Position = 0;
        return gz;
    }

    [Fact]
    public void The_wasm_is_read_from_the_bundle_that_opa_build_writes()
    {
        using var bundle = Bundle(("/data.json", [1]), ("/policy.wasm", [0, 97, 115, 109]), ("/.manifest", [2]));

        Assert.Equal([0, 97, 115, 109], OpaBinaryCompiler.ReadWasm(bundle));
    }

    [Fact]
    public void A_bundle_without_a_wasm_is_a_compile_failure()
    {
        using var bundle = Bundle(("/data.json", [1]));

        Assert.Throws<RegoCompileException>(() => OpaBinaryCompiler.ReadWasm(bundle));
    }

    [Fact]
    public void Without_an_opa_binary_on_the_path_the_compiler_says_it_is_unavailable()
    {
        using var env = new EnvironmentScope(("PATH", Path.GetTempPath() + "no-such-dir"));

        var compiler = new OpaBinaryCompiler();

        Assert.Equal("no opa binary on the PATH", compiler.Unavailable());
    }

    [Fact]
    public void A_refused_builtin_is_named_in_the_compile_error()
    {
        var error = RegoCompileException.From("1 error occurred: p.rego:3: rego_type_error: undefined function http.send\n");

        Assert.Contains("http.send, which reaches outside the process and is refused", error.Message, StringComparison.Ordinal);
        Assert.Equal("some other error", RegoCompileException.From("some other error\n").Message);
    }
}
