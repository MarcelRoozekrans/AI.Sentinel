using AI.Sentinel.ClaudeCode.Policy.Rego;

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

    /// <summary>Compiles the policy in a child process and leaves the result in the shared cache, so a hook run in this
    /// process finds it there and never loads the Go runtime of the interop compiler itself.</summary>
    public static void Prime(string folder, string? cache = null)
    {
        using var policy = RegoPolicy.Load(folder, cache ?? SharedCache, [new ChildProcessCompiler(folder)]);
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
