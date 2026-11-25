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
        RegoPolicyTestSupport.Delete(_cache + ".private");
        RegoPolicyTestSupport.Delete(_folder);
        GC.SuppressFinalize(this);
    }

    private int _compiles;

    // Every compiler is counted, the opa fallback too, so the count does not depend on which one the machine can run.
    private LocalPolicy Load(string? cache = null, params IRegoCompiler[] compilers) =>
        LocalPolicy.Load(
            _folder,
            RegoPolicyTestSupport.Env(cache ?? _cache),
            "/work/repo",
            [.. compilers.Append(new OpaBinaryCompiler()).Select(c => (IRegoCompiler)new CountingCompiler(c, () => ++_compiles))]);

    private LocalPolicy Load(params IRegoCompiler[] compilers) => Load(null, compilers);

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

        Assert.Equal(1, _compiles);
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

        Assert.Equal(2, _compiles);
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
        Assert.Equal(1, _compiles);
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
        Assert.Equal(2, _compiles);
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

        Assert.Throws<InvalidOperationException>(() =>
            LocalPolicy.Load(_folder, RegoPolicyTestSupport.Env(_cache), "/work/repo", [new MissingCompiler()]));
    }

    [Fact]
    public void A_native_library_that_cannot_be_loaded_is_a_platform_error_that_names_the_library_and_the_cause()
    {
        var error = Assert.Throws<PlatformNotSupportedException>(() => Load(new LibraryMissingCompiler()));

        Assert.Contains("Wasmtime", error.Message, StringComparison.Ordinal);
        Assert.Contains("libregoc.so is not here", error.Message, StringComparison.Ordinal);
        Assert.IsType<DllNotFoundException>(error.InnerException);
        Assert.Empty(Directory.GetFiles(_cache));
    }

    private sealed class LibraryMissingCompiler : IRegoCompiler
    {
        public string Name => "native";

        public string? Unavailable() => null;

        public byte[] CompileWasm(PolicySources sources, bool restrictBuiltins) => throw new DllNotFoundException("libregoc.so is not here");
    }

    private static readonly UnixFileMode OwnerOnly = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
    private static readonly UnixFileMode Open = OwnerOnly | UnixFileMode.GroupWrite | UnixFileMode.OtherRead;

    private string PrivateSibling => _cache + ".private";

    [Fact]
    public void An_open_cache_directory_is_never_used_and_never_changed_the_policy_is_cached_in_a_private_sibling()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        Directory.CreateDirectory(_cache);
        var planted = Path.Combine(_cache, "planted.cwasm");
        PolicyCache.Write(planted, [1, 2, 3]);
        File.SetUnixFileMode(_cache, Open);

        try
        {
            using (Load(new ChildProcessCompiler()))
            {
            }

            Assert.Equal(Open, File.GetUnixFileMode(_cache));
            Assert.Equal([1, 2, 3], PolicyCache.TryRead(planted));
            Assert.Equal(OwnerOnly, File.GetUnixFileMode(PrivateSibling));
            Assert.Single(Directory.GetFiles(PrivateSibling, "*.cwasm"));
            Assert.Equal([planted], Directory.GetFiles(_cache));
        }
        finally
        {
            RegoPolicyTestSupport.Delete(PrivateSibling);
        }
    }

    [Fact]
    public void A_native_entry_with_a_valid_digest_in_an_open_cache_directory_is_not_loaded()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        var source = _cache + ".source";
        try
        {
            using (Load(source, new ChildProcessCompiler()))
            {
            }

            Assert.Equal(1, _compiles);
            Directory.CreateDirectory(_cache);
            foreach (var file in Directory.GetFiles(source))
            {
                File.Copy(file, Path.Combine(_cache, Path.GetFileName(file)));
            }

            File.SetUnixFileMode(_cache, Open);

            using var policy = Load(new ChildProcessCompiler());

            Assert.Equal("no rm", Decide(policy).Reason);
            Assert.Equal(2, _compiles);
        }
        finally
        {
            RegoPolicyTestSupport.Delete(source);
            RegoPolicyTestSupport.Delete(PrivateSibling);
        }
    }

    [Fact]
    public void A_directory_that_was_open_stays_unused_after_it_is_made_private()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        Directory.CreateDirectory(_cache);
        File.SetUnixFileMode(_cache, Open);
        try
        {
            var first = PolicyCache.Prepare(_cache);
            File.SetUnixFileMode(_cache, OwnerOnly);

            Assert.Equal(PrivateSibling, first);
            Assert.Equal(PrivateSibling, PolicyCache.Prepare(_cache));
        }
        finally
        {
            RegoPolicyTestSupport.Delete(PrivateSibling);
        }
    }

    [Fact]
    public void Hooks_that_start_together_all_get_the_private_directory_and_none_reads_the_open_one()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        Directory.CreateDirectory(_cache);
        File.SetUnixFileMode(_cache, Open);
        try
        {
            var dirs = Enumerable.Range(0, 16).AsParallel().WithDegreeOfParallelism(16).Select(_ => PolicyCache.Prepare(_cache)).ToArray();

            Assert.All(dirs, d => Assert.Equal(PrivateSibling, d));
            Assert.Equal(OwnerOnly, File.GetUnixFileMode(PrivateSibling));
        }
        finally
        {
            RegoPolicyTestSupport.Delete(PrivateSibling);
        }
    }

    [Fact]
    public void A_private_sibling_that_is_open_blocks_instead_of_being_used()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        Directory.CreateDirectory(_cache);
        File.SetUnixFileMode(_cache, Open);
        Directory.CreateDirectory(PrivateSibling);
        File.SetUnixFileMode(PrivateSibling, Open);
        try
        {
            Assert.Throws<UnauthorizedAccessException>(() => PolicyCache.Prepare(_cache));
        }
        finally
        {
            RegoPolicyTestSupport.Delete(PrivateSibling);
        }
    }

    [Fact]
    public void A_new_cache_directory_is_created_owner_only()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        Assert.Equal(_cache, PolicyCache.Prepare(_cache));
        Assert.Equal(OwnerOnly, File.GetUnixFileMode(_cache));
    }

    [Fact]
    public void An_owner_only_cache_directory_keeps_its_entries()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        Assert.Equal(_cache, PolicyCache.Prepare(_cache));
        var kept = Path.Combine(_cache, "kept.cwasm");
        PolicyCache.Write(kept, [1, 2, 3]);

        Assert.Equal(_cache, PolicyCache.Prepare(_cache));

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

    private const string User = "S-1-5-21-1-2-3-1001";

    [Fact]
    public void A_windows_acl_is_private_when_the_user_owns_it_and_only_the_user_the_system_and_the_administrators_are_allowed()
    {
        PolicyCache.AccessRule[] rules =
        [
            new(Allows: true, Sid: User),
            new(Allows: true, Sid: "S-1-5-18"),
            new(Allows: true, Sid: "S-1-5-32-544"),
            new(Allows: false, Sid: "S-1-1-0"), // a deny rule for Everyone never opens it
            new(Allows: true, Sid: null),       // an identity that is not a SID is not counted
        ];

        Assert.True(PolicyCache.IsPrivate(User, User, rules));
        Assert.True(PolicyCache.IsPrivate(User.ToLowerInvariant(), User, rules));
    }

    [Theory]
    [InlineData("S-1-1-0")]      // Everyone
    [InlineData("S-1-5-32-545")] // Users
    [InlineData("S-1-5-11")]     // Authenticated Users
    [InlineData("S-1-5-21-1-2-3-1002")]
    public void A_windows_acl_that_allows_anyone_else_is_not_private(string other)
    {
        Assert.False(PolicyCache.IsPrivate(User, User, [new(true, User), new(true, other)]));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("S-1-5-32-544")]
    [InlineData("S-1-5-21-1-2-3-1002")]
    public void A_windows_directory_owned_by_someone_else_is_not_private(string? owner)
    {
        Assert.False(PolicyCache.IsPrivate(owner, User, [new(true, User)]));
    }
}
