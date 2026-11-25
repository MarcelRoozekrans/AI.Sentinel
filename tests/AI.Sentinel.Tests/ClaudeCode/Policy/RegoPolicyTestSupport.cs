using System.Diagnostics;
using System.Reflection;
using AI.Sentinel.ClaudeCode.Policy;
using AI.Sentinel.ClaudeCode.Policy.Rego;
using AI.Sentinel.Tests.Helpers;

namespace AI.Sentinel.Tests.ClaudeCode.Policy;

/// <summary>Policy folders, a shared compile cache and the settings that point a hook at them.</summary>
internal static class RegoPolicyTestSupport
{
    private static readonly Lazy<string> Shared = new(() =>
    {
        var dir = Path.Combine(Path.GetTempPath(), "sentinel-rego-tests-" + Guid.NewGuid().ToString("N"));
        AppDomain.CurrentDomain.ProcessExit += (_, _) => Delete(dir);
        return dir;
    });

    /// <summary>One cache for every test that does not test the cache, so a policy is compiled once per test run.</summary>
    public static string SharedCache => Shared.Value;

    public const string Baseline = """
        package sentinel

        import rego.v1

        deny contains "recursive delete" if {
        	input.kind == "shell"
        	some c in input.details.shell.commands
        	c.name == "rm"
        	some a in c.args
        	a in {"-rf", "-fr", "-r"}
        }

        deny contains "write outside the repository" if {
        	input.kind in {"write", "edit"}
        	some p in input.details.paths
        	not p.in_repository
        }

        deny contains sprintf("critical finding from %s (%s)", [f.detector, f.severity]) if {
        	some f in input.findings
        	f.severity == "critical"
        }

        ask contains "git push needs a person" if {
        	input.kind == "shell"
        	some c in input.details.shell.commands
        	c.name == "git"
        	c.args[0] == "push"
        }

        ask contains "network fetch needs a person" if input.kind == "fetch"
        """;

    public const string Guidance = """
        package sentinel

        import rego.v1

        guidance contains "prefer the gh CLI over the GitHub MCP server" if {
        	input.kind == "mcp"
        	input.details.mcp.server == "github"
        }

        allow contains "read inside the repository" if {
        	input.kind in {"read", "search"}
        	every p in input.details.paths {
        		p.in_repository
        	}
        }

        allow contains "read-only shell command" if {
        	input.kind == "shell"
        	count(input.details.shell.commands) > 0
        	every c in input.details.shell.commands {
        		c.name in {"ls", "pwd", "cat"}
        	}
        }
        """;

    /// <summary>A folder with two bundles, the baseline and the team guidance.</summary>
    public static string StandardFolder() => Folder(("org-baseline/baseline.rego", Baseline), ("team-guidance/team.rego", Guidance));

    public static string Folder(params (string Path, string Text)[] files)
    {
        var dir = Path.Combine(Path.GetTempPath(), "sentinel-rego-policy-" + Guid.NewGuid().ToString("N"));
        foreach (var (path, text) in files)
        {
            var full = Path.Combine(dir, path);
            Directory.CreateDirectory(Path.GetDirectoryName(full)!);
            File.WriteAllText(full, text);
        }

        return dir;
    }

    public static Dictionary<string, string?> Env(string? cache = null) =>
        new(StringComparer.Ordinal) { ["SENTINEL_HOOK_POLICY_CACHE_DIR"] = cache ?? SharedCache };

    /// <summary>The compilers a hook has, in its order: the child process, then the <c>opa</c> binary where the interop
    /// compiler has no native library, as on arm64. The <c>opa</c> compiler follows the child's restriction setting, so a
    /// policy loads the same whichever compiler the machine provides.</summary>
    public static IReadOnlyList<IRegoCompiler> Compilers(ChildProcessCompiler child) =>
        [child, new RestrictionOverride(new OpaBinaryCompiler(), child.Unrestricted)];

    /// <summary>Compiles the policy in a child process and leaves the result in the shared cache, so a hook run in this
    /// process finds it there and never loads the Go runtime of the interop compiler itself.</summary>
    public static void Prime(string folder, string? cache = null)
    {
        using var policy = RegoPolicy.Load(folder, cache ?? SharedCache, Compilers(new ChildProcessCompiler()));
    }

    /// <summary>The <c>sentinel-hook</c> assembly in its own output folder, which compiles a policy when started with
    /// <see cref="PolicyCompileCommand.Verb"/>. See the test project for why not the copy next to the tests.</summary>
    public static string HookAssembly
    {
        get
        {
            var configured = typeof(RegoPolicyTestSupport).Assembly.GetCustomAttributes<AssemblyMetadataAttribute>()
                .Single(a => string.Equals(a.Key, "SentinelHookAssembly", StringComparison.Ordinal)).Value!;
            var path = Path.GetFullPath(configured);
            return File.Exists(path) ? path : throw new FileNotFoundException($"sentinel-hook not found at {path}");
        }
    }

    /// <summary>The <c>dotnet</c> host that runs <see cref="HookAssembly"/>.</summary>
    public static string DotnetHost()
    {
        var host = Environment.GetEnvironmentVariable("DOTNET_HOST_PATH");
        if (!string.IsNullOrEmpty(host) && File.Exists(host))
        {
            return host;
        }

        var current = Environment.ProcessPath;
        return current is not null && Path.GetFileNameWithoutExtension(current).Equals("dotnet", StringComparison.OrdinalIgnoreCase) ? current : "dotnet";
    }

    /// <summary>Runs <c>sentinel-hook pre-tool-use</c> as its own process with the policy folder and cache set.</summary>
    public static async Task<(int Exit, string Stdout, string Stderr)> RunHookProcessAsync(
        string folder, string cache, string json, IReadOnlyDictionary<string, string>? extraEnvironment = null)
    {
        var psi = new ProcessStartInfo(DotnetHost())
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        psi.ArgumentList.Add(HookAssembly);
        psi.ArgumentList.Add("pre-tool-use");
        psi.Environment[LocalPolicy.FolderVariable] = folder;
        psi.Environment["SENTINEL_HOOK_POLICY_CACHE_DIR"] = cache;
        psi.Environment[HookAuditTestSupport.SqliteVar] = "off";
        psi.Environment.Remove("SENTINEL_HOOK_AUDIT_NDJSON");
        foreach (var (key, value) in extraEnvironment ?? new Dictionary<string, string>(StringComparer.Ordinal))
        {
            psi.Environment[key] = value;
        }

        using var process = Process.Start(psi)!;
        try
        {
            var stdout = process.StandardOutput.ReadToEndAsync();
            var stderr = process.StandardError.ReadToEndAsync();
            await process.StandardInput.WriteAsync(json);
            process.StandardInput.Close();
            using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(2));
            await process.WaitForExitAsync(timeout.Token);
            return (process.ExitCode, await stdout, await stderr);
        }
        finally
        {
            // A timeout or a failure leaves the hook running, and the using only releases the handle: stop it and reap it.
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
                await process.WaitForExitAsync();
            }
        }
    }

    public static void Delete(string dir)
    {
        try
        {
            Directory.Delete(dir, recursive: true);
        }
        catch (IOException)
        {
            // Best effort: a leftover temporary folder harms nothing.
        }
        catch (UnauthorizedAccessException)
        {
            // As above.
        }
    }
}
