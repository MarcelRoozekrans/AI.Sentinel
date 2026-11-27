using AI.Sentinel.Audit;
using AI.Sentinel.ClaudeCode.Policy.Repository;
using AI.Sentinel.ClaudeCode.Resident;
using AI.Sentinel.Sqlite;
using AI.Sentinel.Tests.ClaudeCode.Repository;
using AI.Sentinel.Tests.ClaudeCode.Resident;
using AI.Sentinel.Tests.Helpers;
using Microsoft.Data.Sqlite;
using Xunit;

namespace AI.Sentinel.Tests.ClaudeCode.Events;

/// <summary>Both hooks route the entries of a call in a repository a node owns, so the resident process can send them (#661). The call
/// is blocked by a damaged approval config, which is audited right after the routing, so no policy or resident process is needed.</summary>
[Collection("NonParallel")]
public sealed class HookEventRoutingTests : IDisposable
{
    private readonly string _root = RepositoryTestSupport.NewDir();
    private readonly string _state = ResidentTestSupport.NewDir();

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        RepositoryTestSupport.Delete(_root);
        ResidentTestSupport.Delete(_state);
    }

    [Theory]
    [InlineData("claude-code")]
    [InlineData("copilot")]
    public async Task A_hook_in_an_owned_repository_routes_its_entries_to_the_node(string cli)
    {
        var owned = RepositoryTestSupport.Repo(_root, "owned", "git@github.com:acme/owned.git");
        var db = Path.Combine(_root, cli + ".db");
        var approvals = Path.Combine(_root, "approvals.json");
        await File.WriteAllTextAsync(approvals, "{ damaged", TestContext.Current.CancellationToken);
        using var env = new EnvironmentScope(
            (ResidentSettings.EnableVariable, "on"), (ResidentSettings.DirectoryVariable, _state),
            ("SENTINEL_HOOK_SERVER_URL", "https://sentinel.example.com"), ("SENTINEL_HOOK_OIDC_ISSUER", "https://login.example.com"),
            ("SENTINEL_HOOK_OIDC_CLIENT_ID", "plugin"), (HookAuditTestSupport.SqliteVar, db), ("SENTINEL_APPROVAL_CONFIG", approvals));
        ResidentState.Open(new ResidentSettings(_state, ResidentSettings.DefaultIdleTimeout, ResidentSettings.DefaultBudget))
            .WriteNodeMap(new NodeMap([new("github.com/acme/owned", "node-a")]));
        var previous = Directory.GetCurrentDirectory();
        Directory.SetCurrentDirectory(owned);
        int exit;
        try
        {
            exit = string.Equals(cli, "copilot", StringComparison.Ordinal)
                ? await AI.Sentinel.Copilot.Cli.Program.RunAsync(
                    ["pre-tool-use"], new StringReader("""{"sessionId":"c-1","toolName":"bash","toolArgs":"{\"command\":\"ls\"}"}"""),
                    new StringWriter(), new StringWriter())
                : await AI.Sentinel.ClaudeCode.Cli.Program.RunAsync(
                    ["pre-tool-use"], new StringReader("""{"session_id":"cc-1","tool_name":"Bash","tool_input":{"command":"ls"}}"""),
                    new StringWriter(), new StringWriter());
        }
        finally
        {
            Directory.SetCurrentDirectory(previous);
        }

        Assert.Equal(2, exit);
        await using var store = new SqliteAuditStore(new SqliteAuditStoreOptions { DatabasePath = db });
        var entries = new List<AuditEntry>();
        await foreach (var e in store.QueryAsync(new AuditQuery { PageSize = 10 }, CancellationToken.None))
        {
            entries.Add(e);
        }

        Assert.NotEmpty(entries);
        Assert.All(entries, e => Assert.Equal(("shell", "node-a"), (e.ToolKind, e.Node)));
    }
}
