using AI.Sentinel.ClaudeCode;
using AI.Sentinel.ClaudeCode.Policy.Rego;
using AI.Sentinel.ClaudeCode.Policy.Repository;

namespace AI.Sentinel.Tests.ClaudeCode.Repository;

/// <summary>Git folders written as git leaves them, and node policies that answer from a table.</summary>
internal static class RepositoryTestSupport
{
    public static string NewDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), "sentinel-repo-" + Guid.NewGuid().ToString("N")[..12]);
        Directory.CreateDirectory(dir);
        return dir;
    }

    public static void Delete(string dir)
    {
        try
        {
            Directory.Delete(dir, recursive: true);
        }
        catch (IOException)
        {
            // Best effort.
        }
    }

    public static string Config(string url, string remote = "origin") =>
        $"[core]\n\trepositoryformatversion = 0\n[remote \"{remote}\"]\n\turl = {url}\n\tfetch = +refs/heads/*:refs/remotes/{remote}/*\n[branch \"main\"]\n\tremote = {remote}\n";

    /// <summary>A repository folder whose <c>.git/config</c> names <paramref name="url"/>.</summary>
    public static string Repo(string root, string name, string url)
    {
        var dir = Path.Combine(root, name);
        Directory.CreateDirectory(Path.Combine(dir, ".git"));
        File.WriteAllText(Path.Combine(dir, ".git", "config"), Config(url));
        return dir;
    }

    /// <summary>A policy set that answers from <paramref name="organisation"/> and <paramref name="nodes"/>, both given the input.</summary>
    internal sealed class FakePolicies(Func<string, RegoDecision?> organisation, Func<string, string, RegoDecision?> nodes) : INodePolicies
    {
        public int Calls { get; private set; }

        public RegoDecision? Organisation(string inputJson)
        {
            Calls++;
            return organisation(inputJson);
        }

        public RegoDecision? ForRepository(string repository, string inputJson)
        {
            Calls++;
            return nodes(repository, inputJson);
        }
    }

    public static RegoDecision Decision(DecisionOutcome outcome, string reason) => new(outcome, [reason]);
}
