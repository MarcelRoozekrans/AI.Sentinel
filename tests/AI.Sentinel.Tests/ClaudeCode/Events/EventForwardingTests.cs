using System.Globalization;
using System.Net;
using System.Text.Json;
using AI.Sentinel.Audit;
using AI.Sentinel.ClaudeCode;
using AI.Sentinel.ClaudeCode.Events;
using AI.Sentinel.ClaudeCode.Policy;
using AI.Sentinel.ClaudeCode.Policy.Repository;
using AI.Sentinel.ClaudeCode.Resident;
using AI.Sentinel.Detection;
using AI.Sentinel.Sqlite;
using AI.Sentinel.Sqlite.Local;
using AI.Sentinel.Tests.ClaudeCode.Repository;
using AI.Sentinel.Tests.ClaudeCode.Resident;
using Microsoft.Data.Sqlite;
using Xunit;

namespace AI.Sentinel.Tests.ClaudeCode.Events;

/// <summary>The resident process forwards the local audit to the server (#661): allowlisted fields only, in order and once, nothing for
/// a repository in strict mode, a gap for what was pruned, and no effect on a decision when the server is away.</summary>
[Collection("NonParallel")]
public sealed class EventForwardingTests : IDisposable
{
    private static readonly Uri Endpoint = new("https://sentinel.example.com/ai-sentinel/events/ingest");

    private static readonly string[] Allowlist =
    [
        "event_id", "at", "tool_kind", "outcome", "policies", "policy_version", "decided", "node", "cli", "session", "detector",
        "severity", "redactions", "reason",
    ];

    private readonly string _dir = ResidentTestSupport.NewDir();
    private readonly string _db;
    private readonly EventServerStub _server = new();
    private readonly SqliteAuditStore _store;
    private bool _detailed;

    public EventForwardingTests()
    {
        Directory.CreateDirectory(_dir);
        _db = Path.Combine(_dir, "audit.db");
        _store = new SqliteAuditStore(new SqliteAuditStoreOptions { DatabasePath = _db });
    }

    public void Dispose()
    {
        _store.DisposeAsync().AsTask().GetAwaiter().GetResult();
        SqliteConnection.ClearAllPools();
        ResidentTestSupport.Delete(_dir);
    }

    private EventForwarder Forwarder(int batchSize = 200) => new(
        new SqliteAuditSource(_db), new EventCursor(_dir), new HttpClient(_server), Endpoint, () => "acme", _ => _detailed, null, batchSize);

    private static AuditEntry Entry(string detector, Severity severity, string summary, string? toolKind = "shell", string? code = null, string? node = "node-a") =>
        new(Guid.NewGuid().ToString("N"), DateTimeOffset.UtcNow, string.Empty, null, severity, detector, summary)
        {
            ToolKind = toolKind,
            Node = node,
            SessionId = "s-1",
            Source = "claude-code",
            PolicyCode = code,
        };

    private Task AppendAsync(AuditEntry entry) => _store.AppendAsync(entry, CancellationToken.None).AsTask();

    private async Task AppendManyAsync(int count, string prefix = "f")
    {
        for (var i = 0; i < count; i++)
        {
            await AppendAsync(Entry("SEC-01", Severity.High, $"{prefix}{i}"));
        }
    }

    private async Task PruneThroughAsync(long sequence)
    {
        await using var connection = new SqliteConnection($"Data Source={_db};Pooling=False");
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = $"DELETE FROM audit_entries WHERE sequence <= {sequence.ToString(CultureInfo.InvariantCulture)};";
        await command.ExecuteNonQueryAsync();
    }

    [Fact]
    public async Task Each_kind_of_entry_is_sent_with_the_allowlisted_fields_only()
    {
        var outcome = OutcomeAudit.Entry(
            new OutcomeDecision(DecisionOutcome.Deny, "no force push to main", ["node:a", "organisation"], "v7", OutcomeDecision.Resident), "s-1") with
        {
            ToolKind = "shell",
            Node = "node-a",
            Source = "claude-code",
        };
        await AppendAsync(outcome);
        await AppendAsync(Entry("SEC-01", Severity.High, "Prompt injection found in rm -rf /home/someone/secrets"));
        await AppendAsync(Entry("SEC-23", Severity.None, "Redacted 2 EMAIL, 1 IBAN", "fetch", AuditEntryRedactionExtensions.RedactedPolicyCode));
        await AppendAsync(Entry("AUTHZ-DENY", Severity.High, "Caller 'marcel' denied for tool 'Bash'", "shell", "approval_required"));

        var result = await Forwarder().ForwardAsync(CancellationToken.None);

        Assert.False(result.Failed);
        Assert.Equal(4, result.Sent);
        var events = _server.Events.ToList();
        Assert.All(events, e => Assert.All(e.EnumerateObject(), p => Assert.Contains(p.Name, Allowlist, StringComparer.Ordinal)));
        Assert.Equal(Guid.Parse(outcome.Id).ToString("D"), events[0].GetProperty("event_id").GetString());
        Assert.Equal("deny", events[0].GetProperty("outcome").GetString());
        Assert.Equal(["node:a", "organisation"], events[0].GetProperty("policies").EnumerateArray().Select(p => p.GetString()!).ToList());
        Assert.Equal("v7", events[0].GetProperty("policy_version").GetString());
        Assert.Equal("resident", events[0].GetProperty("decided").GetString());
        Assert.Equal("node-a", events[0].GetProperty("node").GetString());
        Assert.Equal("claude-code", events[0].GetProperty("cli").GetString());
        Assert.Equal("s-1", events[0].GetProperty("session").GetString());
        Assert.Equal("finding", events[1].GetProperty("outcome").GetString());
        Assert.Equal("SEC-01", events[1].GetProperty("detector").GetString());
        Assert.Equal("high", events[1].GetProperty("severity").GetString());
        Assert.Equal(2, events[2].GetProperty("redactions").GetProperty("EMAIL").GetInt32());
        Assert.Equal(1, events[2].GetProperty("redactions").GetProperty("IBAN").GetInt32());
        Assert.Equal("ask", events[3].GetProperty("outcome").GetString());
        Assert.Equal("acme", _server.Batches[0].GetProperty("organisation").GetString());
    }

    [Fact]
    public async Task No_command_path_or_summary_text_is_sent_without_detailed_logging()
    {
        await AppendAsync(Entry("SEC-01", Severity.High, "found in rm -rf /home/someone/secrets"));
        await AppendAsync(OutcomeAudit.Entry(new OutcomeDecision(DecisionOutcome.Deny, "blocked /etc/passwd", ["node:a"]), "s-1") with { ToolKind = "read" });

        await Forwarder().ForwardAsync(CancellationToken.None);

        Assert.All(_server.Events, e => Assert.False(e.TryGetProperty("reason", out _)));
        Assert.DoesNotContain("/home", string.Join("", _server.Batches.Select(b => b.GetRawText())), StringComparison.Ordinal);
        Assert.DoesNotContain("passwd", string.Join("", _server.Batches.Select(b => b.GetRawText())), StringComparison.Ordinal);
    }

    [Fact]
    public async Task With_detailed_logging_the_reason_is_sent_redacted()
    {
        _detailed = true;
        await AppendAsync(OutcomeAudit.Entry(
            new OutcomeDecision(DecisionOutcome.Deny, "may not read /home/someone/.ssh/id_rsa for 'prod' at https://example.com/x", ["node:a"]), "s-1") with
        {
            ToolKind = "read",
            Node = "node-a",
        });

        await Forwarder().ForwardAsync(CancellationToken.None);

        var reason = Assert.Single(_server.Events).GetProperty("reason").GetString();
        Assert.Equal("may not read <path> for <value> at <url>", reason);
    }

    [Fact]
    public async Task Entries_without_a_route_are_not_sent_which_is_what_strict_repository_mode_does()
    {
        await AppendAsync(Entry("SEC-01", Severity.High, "found", toolKind: null));
        await AppendAsync(Entry("SEC-01", Severity.High, "found too", toolKind: null));

        var result = await Forwarder().ForwardAsync(CancellationToken.None);

        Assert.Equal(0, result.Sent);
        Assert.Empty(_server.Batches);
        Assert.Equal(2, new EventCursor(_dir).Read());
    }

    [Fact]
    public void A_call_in_strict_mode_is_not_routed_and_an_owned_one_is()
    {
        var root = RepositoryTestSupport.NewDir();
        try
        {
            var state = ResidentTestSupport.NewDir();
            var env = new Dictionary<string, string?>(StringComparer.Ordinal)
            {
                [ResidentSettings.EnableVariable] = "on",
                [ResidentSettings.DirectoryVariable] = state,
                ["SENTINEL_HOOK_SERVER_URL"] = "https://sentinel.example.com",
                ["SENTINEL_HOOK_OIDC_ISSUER"] = "https://login.example.com",
                ["SENTINEL_HOOK_OIDC_CLIENT_ID"] = "plugin",
            };
            ResidentState.Open(ResidentSettings.FromEnvironment(env)!).WriteNodeMap(new NodeMap([new("github.com/acme/owned", "node-a")]));
            var owned = RepositoryTestSupport.Repo(root, "owned", "git@github.com:acme/owned.git");
            var stranger = RepositoryTestSupport.Repo(root, "stranger", "git@github.com:acme/stranger.git");

            Assert.Equal(("shell", "node-a"), EventRouting.Resolve(env, PolicyClis.ClaudeCode, "Bash", owned));
            Assert.Null(EventRouting.Resolve(env, PolicyClis.ClaudeCode, "Bash", stranger));
            Assert.Null(EventRouting.Resolve(env, PolicyClis.ClaudeCode, "Bash", root));
            env["SENTINEL_HOOK_STRICT_REPOSITORY"] = "off";
            Assert.Equal(("shell", null), EventRouting.Resolve(env, PolicyClis.ClaudeCode, "Bash", stranger));
            ResidentTestSupport.Delete(state);
        }
        finally
        {
            RepositoryTestSupport.Delete(root);
        }
    }

    [Fact]
    public void With_none_of_the_settings_nothing_is_routed_and_no_forwarder_exists()
    {
        var env = new Dictionary<string, string?>(StringComparer.Ordinal) { [ResidentSettings.EnableVariable] = "on", [ResidentSettings.DirectoryVariable] = _dir };

        Assert.Null(EventRouting.Resolve(env, PolicyClis.ClaudeCode, "Bash", _dir));
        Assert.Null(EventForwarding.Open(env, ResidentSettings.FromEnvironment(env)!, tokens: null, inner: null, TextWriter.Null));
    }

    [Fact]
    public async Task A_hook_routes_its_entries_only_when_told_to()
    {
        var path = Path.Combine(_dir, "routed.db");
        var settings = new LocalAuditSettings(path, null, null);
        await using (var session = LocalAudit.Open(settings, "claude-code"))
        {
            await session.Store.AppendAsync(Entry("A", Severity.Low, "before", toolKind: null), CancellationToken.None);
            session.RouteEvents("shell", "node-a");
            await session.Store.AppendAsync(Entry("B", Severity.Low, "after", toolKind: null), CancellationToken.None);
        }

        await using var read = new SqliteAuditStore(new SqliteAuditStoreOptions { DatabasePath = path });
        var entries = new List<AuditEntry>();
        await foreach (var e in read.QueryAsync(new AuditQuery { PageSize = 10 }, CancellationToken.None))
        {
            entries.Add(e);
        }

        Assert.Null(entries[0].ToolKind);
        Assert.Equal("shell", entries[1].ToolKind);
        Assert.Equal("node-a", entries[1].Node);
    }

    [Fact]
    public async Task Events_made_while_the_server_is_away_arrive_in_order_and_once_with_the_same_ids()
    {
        await AppendManyAsync(3);
        _server.Down = true;
        var failed = await Forwarder().ForwardAsync(CancellationToken.None);
        Assert.True(failed.Failed);
        Assert.Null(new EventCursor(_dir).Read());

        await AppendManyAsync(2, "g");
        _server.Down = false;
        var forwarder = Forwarder(batchSize: 2);
        var first = await forwarder.ForwardAsync(CancellationToken.None);
        var second = await forwarder.ForwardAsync(CancellationToken.None);

        Assert.Equal(5, first.Sent);
        Assert.Equal(0, second.Sent);
        var ids = _server.Events.Select(e => e.GetProperty("event_id").GetString()).ToList();
        Assert.Equal(5, ids.Count);
        Assert.Equal(5, ids.Distinct(StringComparer.Ordinal).Count());
        Assert.All(_server.Batches, b => Assert.False(b.TryGetProperty("gap", out _)));
        var stored = new List<string?>();
        await foreach (var e in _store.QueryAsync(new AuditQuery { PageSize = 10 }, CancellationToken.None))
        {
            stored.Add(Guid.Parse(e.Id).ToString("D"));
        }

        Assert.Equal(stored, ids);
    }

    [Fact]
    public async Task A_batch_that_is_sent_again_keeps_its_event_ids()
    {
        await AppendManyAsync(2);
        _server.Status = HttpStatusCode.ServiceUnavailable;
        var failed = await Forwarder().ForwardAsync(CancellationToken.None);
        _server.Status = HttpStatusCode.OK;
        await Forwarder().ForwardAsync(CancellationToken.None);
        _server.Status = HttpStatusCode.OK;

        Assert.True(failed.Failed);
        Assert.Equal(2, _server.Events.Count());
        // The refused request carried the same entries: forward them to a second server and compare the ids.
        var again = new EventServerStub();
        new EventCursor(_dir).Write(0);
        await new EventForwarder(new SqliteAuditSource(_db), new EventCursor(_dir), new HttpClient(again), Endpoint, () => "acme", _ => false).ForwardAsync(CancellationToken.None);
        Assert.Equal(
            _server.Events.Select(e => e.GetProperty("event_id").GetString()!).ToList(),
            again.Events.Select(e => e.GetProperty("event_id").GetString()!).ToList());
    }

    [Fact]
    public async Task A_failed_send_never_throws_and_leaves_the_queue_as_it_was()
    {
        await AppendManyAsync(2);
        var forwarder = Forwarder();

        _server.Down = true;
        Assert.True((await forwarder.TryForwardAsync(CancellationToken.None)).Failed);
        _server.Down = false;
        _server.Status = HttpStatusCode.InternalServerError;
        Assert.True((await forwarder.TryForwardAsync(CancellationToken.None)).Failed);
        var broken = new EventForwarder(new ThrowingSource(), new EventCursor(_dir), new HttpClient(_server), Endpoint, () => "acme", _ => false);
        Assert.True((await broken.TryForwardAsync(CancellationToken.None)).Failed);

        Assert.Null(new EventCursor(_dir).Read());
        _server.Status = HttpStatusCode.OK;
        Assert.Equal(2, (await forwarder.ForwardAsync(CancellationToken.None)).Sent);
    }

    [Fact]
    public async Task Entries_pruned_before_they_were_sent_are_reported_as_a_gap_with_a_count()
    {
        await AppendManyAsync(3);
        await Forwarder().ForwardAsync(CancellationToken.None);
        await AppendManyAsync(4, "g");
        await PruneThroughAsync(5);

        var result = await Forwarder().ForwardAsync(CancellationToken.None);

        Assert.Equal(2, result.Pruned);
        Assert.Equal(2, result.Sent);
        var gap = _server.Batches[^1].GetProperty("gap");
        Assert.Equal(2, gap.GetProperty("pruned").GetInt32());
        Assert.Equal("node-a", gap.GetProperty("node").GetString());
    }

    [Fact]
    public async Task A_gap_is_reported_again_if_its_batch_was_not_taken()
    {
        await AppendManyAsync(1);
        await Forwarder().ForwardAsync(CancellationToken.None);
        await AppendManyAsync(3, "g");
        await PruneThroughAsync(3);
        _server.Down = true;
        await Forwarder().ForwardAsync(CancellationToken.None);
        _server.Down = false;

        await Forwarder().ForwardAsync(CancellationToken.None);

        Assert.Equal(2, _server.Batches[^1].GetProperty("gap").GetProperty("pruned").GetInt32());
        Assert.Equal(2, _server.Batches.Count);
    }

    [Fact]
    public async Task With_no_cap_an_outage_loses_nothing_and_reports_no_gap()
    {
        // The audit store prunes only when a cap is set; SENTINEL_HOOK_AUDIT_MAX_MB=0 sets none, so every unsent entry waits.
        var settings = LocalAudit.ReadSettings(
            new Dictionary<string, string?>(StringComparer.Ordinal) { ["SENTINEL_HOOK_AUDIT_MAX_MB"] = "0", ["SENTINEL_HOOK_AUDIT_SQLITE"] = _db },
            "SENTINEL_HOOK_", _db, []);
        Assert.Null(settings.MaxDatabaseSizeBytes);
        await using (var session = LocalAudit.Open(settings, "claude-code"))
        {
            session.RouteEvents("shell", "node-a");
            for (var i = 0; i < 300; i++)
            {
                await session.Store.AppendAsync(Entry("SEC-01", Severity.High, $"f{i}", toolKind: null), CancellationToken.None);
            }
        }

        _server.Down = true;
        await Forwarder().TryForwardAsync(CancellationToken.None);
        _server.Down = false;
        var result = await Forwarder().ForwardAsync(CancellationToken.None);

        Assert.Equal(300, result.Sent);
        Assert.Equal(0, result.Pruned);
        Assert.All(_server.Batches, b => Assert.False(b.TryGetProperty("gap", out _)));
    }

    [Fact]
    public async Task A_replaced_audit_file_starts_again_without_a_gap()
    {
        await AppendManyAsync(3);
        await Forwarder().ForwardAsync(CancellationToken.None);
        await PruneThroughAsync(100);
        await using (var connection = new SqliteConnection($"Data Source={_db};Pooling=False"))
        {
            await connection.OpenAsync(TestContext.Current.CancellationToken);
            await using var command = connection.CreateCommand();
            command.CommandText = "DELETE FROM audit_entries;";
            await command.ExecuteNonQueryAsync(TestContext.Current.CancellationToken);
        }

        Assert.Equal(0, (await Forwarder().ForwardAsync(CancellationToken.None)).Sent);
        Assert.Equal(0, new EventCursor(_dir).Read());
        await AppendManyAsync(1, "n");
        var result = await Forwarder().ForwardAsync(CancellationToken.None);

        Assert.Equal(1, result.Sent);
        Assert.Equal(0, result.Pruned);
    }

    [Fact]
    public async Task Nothing_is_sent_before_the_developer_has_signed_in()
    {
        await AppendManyAsync(1);
        var forwarder = new EventForwarder(new SqliteAuditSource(_db), new EventCursor(_dir), new HttpClient(_server), Endpoint, () => null, _ => false);

        var result = await forwarder.ForwardAsync(CancellationToken.None);

        Assert.True(result.Failed);
        Assert.Empty(_server.Batches);
    }

    private sealed class ThrowingSource : IAuditSource
    {
        public Task<AuditPage> ReadAfterAsync(long after, int limit, CancellationToken ct) => throw new InvalidOperationException("boom");
    }
}
