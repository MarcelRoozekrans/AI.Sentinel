using AI.Sentinel.ClaudeCode.Policy.Rego;
using Xunit;

namespace AI.Sentinel.Tests.ClaudeCode.Policy;

public class PolicySourcesTests : IDisposable
{
    private readonly string _folder = RegoPolicyTestSupport.StandardFolder();

    public void Dispose()
    {
        RegoPolicyTestSupport.Delete(_folder);
        GC.SuppressFinalize(this);
    }

    [Fact]
    public void The_version_is_stable_across_loads_and_changes_when_one_bundle_changes()
    {
        var first = PolicySources.Load(_folder);
        var again = PolicySources.Load(_folder);
        File.AppendAllText(Path.Combine(_folder, "team-guidance", "team.rego"), "\n# changed\n");
        var changed = PolicySources.Load(_folder);

        Assert.Equal(first.Hash, again.Hash);
        Assert.NotEqual(first.Hash, changed.Hash, StringComparer.Ordinal);
        Assert.Equal(first.Hash[..16], first.Version);
    }

    [Fact]
    public void Line_endings_do_not_change_the_version()
    {
        var unix = PolicySources.Load(_folder);
        foreach (var file in Directory.GetFiles(_folder, "*.rego", SearchOption.AllDirectories))
        {
            File.WriteAllText(file, File.ReadAllText(file).Replace("\n", "\r\n", StringComparison.Ordinal));
        }

        Assert.Equal(unix.Hash, PolicySources.Load(_folder).Hash);
    }

    [Fact]
    public void Bundles_are_the_subfolders_and_a_file_at_the_top_is_a_bundle_of_its_own()
    {
        File.WriteAllText(Path.Combine(_folder, "extras.rego"), "package sentinel\nimport rego.v1\nallow contains \"x\" if true\n");

        var sources = PolicySources.Load(_folder);

        Assert.Equal(["extras", "org-baseline", "team-guidance"], sources.Bundles);
        Assert.Contains(sources.Files, f => string.Equals(f.Path, "_sentinel_host/decision.rego", StringComparison.Ordinal));
    }
}
