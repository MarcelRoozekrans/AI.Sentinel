using System.Text.Json;
using AI.Sentinel.ClaudeCode;
using AI.Sentinel.ClaudeCode.Policy;
using AI.Sentinel.ClaudeCode.Policy.Rego;
using Xunit;

namespace AI.Sentinel.Tests.ClaudeCode.Policy;

/// <summary>The compiled policy is cached per user under the hash of its sources, checked by digest before it is loaded, and
/// rebuilt when it is missing or damaged. It is never skipped, and a policy that cannot be had is never a defer.</summary>
[Collection("NonParallel")]
public class RegoPolicyCacheTests : IDisposable
{
    private readonly string _cache = Path.Combine(Path.GetTempPath(), "sentinel-rego-cache-" + Guid.NewGuid().ToString("N"));
    private readonly string _folder = RegoPolicyTestSupport.Folder(
        ("p/a.rego", "package sentinel\nimport rego.v1\ndeny contains \"no rm\" if {\n\tsome c in input.details.shell.commands\n\tc.name == \"rm\"\n}\n"));

    public void Dispose()
    {
        RegoPolicyTestSupport.Delete(_cache);
        RegoPolicyTestSupport.Delete(_folder);
        GC.SuppressFinalize(this);
    }

    private LocalPolicy Load(params IRegoCompiler[] compilers) =>
        LocalPolicy.Load(_folder, RegoPolicyTestSupport.Env(_cache), "/work/repo", [.. compilers, new OpaBinaryCompiler()]);

    private static HookOutput Decide(LocalPolicy policy) =>
        policy.Decide(new HookOutput { Decision = HookDecision.Allow }, PolicyClis.ClaudeCode, "Bash", JsonDocument.Parse("""{"command":"rm x"}""").RootElement, "s");

    private string[] Files(string pattern) => Directory.GetFiles(_cache, pattern);

    [Fact]
    public void The_first_load_compiles_and_the_next_ones_load_the_cached_native_code()
    {
        var compiler = new ChildProcessCompiler();

        using (var first = Load(compiler))
        {
            Assert.Equal("no rm", Decide(first).Reason);
        }

        using (var second = Load(compiler))
        {
            Assert.Equal("no rm", Decide(second).Reason);
        }

        Assert.Equal(1, compiler.Compiles);
        Assert.Single(Files("*.wasm"));
        var native = Assert.Single(Files("*.cwasm"));
        Assert.Contains("wasmtime", Path.GetFileName(native), StringComparison.Ordinal);
        Assert.Contains(WasmEngine.Settings, Path.GetFileName(native), StringComparison.Ordinal);
    }

    [Fact]
    public void A_change_to_the_policy_is_a_new_cache_entry()
    {
        var compiler = new ChildProcessCompiler();
        using (Load(compiler))
        {
        }

        File.AppendAllText(Path.Combine(_folder, "p", "a.rego"), "\n# edited\n");
        using (Load(compiler))
        {
        }

        Assert.Equal(2, compiler.Compiles);
        Assert.Equal(2, Files("*.cwasm").Length);
    }

    [Fact]
    public void Native_code_that_does_not_match_its_digest_is_not_loaded_and_is_rebuilt_from_the_cached_module()
    {
        var compiler = new ChildProcessCompiler();
        using (Load(compiler))
        {
        }

        var native = Assert.Single(Files("*.cwasm"));
        var bytes = File.ReadAllBytes(native);
        bytes[^1] ^= 0xFF;
        File.WriteAllBytes(native, bytes);

        using var policy = Load(compiler);

        Assert.Equal("no rm", Decide(policy).Reason);
        Assert.Equal(1, compiler.Compiles);
        Assert.NotNull(PolicyCache.TryRead(native));
    }

    [Fact]
    public void A_damaged_cache_is_rebuilt_by_compiling_again()
    {
        var compiler = new ChildProcessCompiler();
        using (Load(compiler))
        {
        }

        foreach (var file in Directory.GetFiles(_cache))
        {
            File.WriteAllBytes(file, [1, 2, 3]);
        }

        using var policy = Load(compiler);

        Assert.Equal("no rm", Decide(policy).Reason);
        Assert.Equal(2, compiler.Compiles);
    }

    [Fact]
    public void A_damaged_cache_and_no_compiler_blocks_instead_of_loading_what_failed_its_digest()
    {
        using (Load(new ChildProcessCompiler()))
        {
        }

        foreach (var file in Directory.GetFiles(_cache))
        {
            var bytes = File.ReadAllBytes(file);
            bytes[40] ^= 0xFF;
            File.WriteAllBytes(file, bytes);
        }

        Assert.Throws<InvalidOperationException>(() => Load(new MissingCompiler()));
    }

    [Fact]
    public void The_cache_directory_is_owner_only_on_unix_even_when_it_was_created_open()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        Directory.CreateDirectory(_cache);
        File.SetUnixFileMode(_cache, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute | UnixFileMode.GroupWrite | UnixFileMode.OtherWrite | UnixFileMode.OtherRead);

        using (Load(new ChildProcessCompiler()))
        {
        }

        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute, File.GetUnixFileMode(_cache));
    }

    [Fact]
    public void An_open_cache_directory_loses_its_entries_because_another_user_could_have_written_them()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        Directory.CreateDirectory(_cache);
        var planted = Path.Combine(_cache, "planted.cwasm");
        PolicyCache.Write(planted, [1, 2, 3]);
        File.SetUnixFileMode(_cache, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute | UnixFileMode.GroupWrite);

        PolicyCache.Prepare(_cache);

        Assert.False(File.Exists(planted));
        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute, File.GetUnixFileMode(_cache));
    }

    [Fact]
    public void An_owner_only_cache_directory_keeps_its_entries()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        PolicyCache.Prepare(_cache);
        var kept = Path.Combine(_cache, "kept.cwasm");
        PolicyCache.Write(kept, [1, 2, 3]);

        PolicyCache.Prepare(_cache);

        Assert.Equal([1, 2, 3], PolicyCache.TryRead(kept));
    }

    [Fact]
    public void The_default_cache_lives_under_the_local_application_data_of_the_user_and_a_setting_moves_it()
    {
        var dir = PolicyCache.DefaultDirectory(new Dictionary<string, string?>(StringComparer.Ordinal));

        Assert.EndsWith(Path.Combine("ai-sentinel", "policy-cache"), dir, StringComparison.Ordinal);
        Assert.Equal("/elsewhere", PolicyCache.DefaultDirectory(new Dictionary<string, string?>(StringComparer.Ordinal) { ["SENTINEL_HOOK_POLICY_CACHE_DIR"] = "/elsewhere" }), StringComparer.Ordinal);
        Assert.Equal(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Path.GetDirectoryName(Path.GetDirectoryName(dir)),
            StringComparer.Ordinal);
    }

    [Fact]
    public void A_file_with_a_digest_reads_back_and_a_short_or_missing_file_reads_as_absent()
    {
        Directory.CreateDirectory(_cache);
        var path = Path.Combine(_cache, "x.bin");
        PolicyCache.Write(path, [9, 8, 7]);

        Assert.Equal([9, 8, 7], PolicyCache.TryRead(path));
        Assert.Null(PolicyCache.TryRead(Path.Combine(_cache, "missing.bin")));
        File.WriteAllBytes(path, [1, 2]);
        Assert.Null(PolicyCache.TryRead(path));
        Assert.Empty(Files("*.tmp"));
    }
}
