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

    // A stand-in for opa, a shell script, so the process handling is tested where no opa binary is installed.
    [System.Runtime.Versioning.UnsupportedOSPlatform("windows")]
    private static string Stub(string dir, string script)
    {
        var stub = Path.Combine(dir, "opa");
        File.WriteAllText(stub, "#!/bin/sh\n" + script);
        File.SetUnixFileMode(stub, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        return stub;
    }

    private static readonly PolicySources Sources = new([new PolicyFile("a.rego", "package sentinel\n")], ["a"], new string('a', 64));

    [Fact]
    public void An_opa_build_that_fails_is_a_compile_error_with_what_opa_printed()
    {
        if (OperatingSystem.IsWindows())
        {
            return; // the stub is a shell script
        }

        var dir = Directory.CreateTempSubdirectory("sentinel-opa-stub-").FullName;
        try
        {
            var stub = Stub(dir, "echo '1 error occurred: a.rego:1: rego_parse_error: unexpected eof'\necho 'warning' >&2\nexit 1\n");
            var compiler = new OpaBinaryCompiler(stub, TimeSpan.FromSeconds(30));

            var error = Assert.Throws<RegoCompileException>(() => compiler.CompileWasm(Sources, restrictBuiltins: false));

            Assert.Equal("1 error occurred: a.rego:1: rego_parse_error: unexpected eof\nwarning", error.Message);
        }
        finally
        {
            RegoPolicyTestSupport.Delete(dir);
        }
    }

    [Fact]
    public void The_module_is_read_from_the_bundle_opa_build_wrote_to_its_output_argument()
    {
        if (OperatingSystem.IsWindows())
        {
            return; // the stub is a shell script
        }

        var dir = Directory.CreateTempSubdirectory("sentinel-opa-stub-").FullName;
        try
        {
            var prepared = Path.Combine(dir, "prepared.tar.gz");
            using (var bundle = Bundle(("/policy.wasm", [0, 97, 115, 109, 1])))
            {
                File.WriteAllBytes(prepared, bundle.ToArray());
            }

            // opa build -t wasm -e <entrypoint> -o <bundle> [--capabilities <file>] <root>: the output is the seventh argument.
            var stub = Stub(dir, $"cp '{prepared}' \"$7\"\n");
            var compiler = new OpaBinaryCompiler(stub, TimeSpan.FromSeconds(30));

            Assert.Equal([0, 97, 115, 109, 1], compiler.CompileWasm(Sources, restrictBuiltins: true));
        }
        finally
        {
            RegoPolicyTestSupport.Delete(dir);
        }
    }

    [Fact]
    public void An_opa_that_stalls_is_stopped_at_the_deadline()
    {
        if (OperatingSystem.IsWindows())
        {
            return; // the stub is a shell script
        }

        var dir = Directory.CreateTempSubdirectory("sentinel-opa-stub-").FullName;
        try
        {
            var stub = Path.Combine(dir, "opa");
            File.WriteAllText(stub, "#!/bin/sh\nsleep 60\n");
            File.SetUnixFileMode(stub, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            var compiler = new OpaBinaryCompiler(stub, TimeSpan.FromSeconds(1));
            var sources = new PolicySources([new PolicyFile("a.rego", "package sentinel\n")], ["a"], new string('a', 64));

            var watch = System.Diagnostics.Stopwatch.StartNew();
            var error = Assert.Throws<TimeoutException>(() => compiler.CompileWasm(sources, restrictBuiltins: true));

            Assert.True(watch.Elapsed < TimeSpan.FromSeconds(30), $"took {watch.Elapsed}");
            Assert.Contains("opa", error.Message, StringComparison.Ordinal);
        }
        finally
        {
            RegoPolicyTestSupport.Delete(dir);
        }
    }
}
