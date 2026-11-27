using System.Text;
using AI.Sentinel.Audit;
using AI.Sentinel.ClaudeCode;
using AI.Sentinel.ClaudeCode.Events;
using AI.Sentinel.ClaudeCode.Policy;
using AI.Sentinel.ClaudeCode.Policy.Rego;
using AI.Sentinel.ClaudeCode.Policy.Repository;
using AI.Sentinel.ClaudeCode.Resident;
using AI.Sentinel.ClaudeCode.SignIn;
using AI.Sentinel.Detection;
using AI.Sentinel.Profiles;
using AI.Sentinel.Sqlite;
using AI.Sentinel.Tests.ClaudeCode.Repository;
using AI.Sentinel.Tests.ClaudeCode.Resident;
using Microsoft.Data.Sqlite;
using Xunit;

namespace AI.Sentinel.Tests.ClaudeCode.Events;

/// <summary>The forwarder built from the settings of the resident process, and what it does when its own files cannot be used (#661).</summary>
[Collection("NonParallel")]
public sealed class EventForwardingFailureTests : IDisposable
{
    private static readonly Uri Endpoint = new("https://sentinel.example.com/ai-sentinel/events/ingest");

    private readonly string _dir = ResidentTestSupport.NewDir();
    private readonly string _db;
    private readonly EventServerStub _server = new();

    public EventForwardingFailureTests()
    {
        Directory.CreateDirectory(_dir);
        _db = Path.Combine(_dir, "audit.db");
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        ResidentTestSupport.Delete(_dir);
    }

    private async Task AppendAsync(string summary)
    {
        await using var store = new SqliteAuditStore(new SqliteAuditStoreOptions { DatabasePath = _db });
        await store.AppendAsync(
            new AuditEntry(Guid.NewGuid().ToString("N"), DateTimeOffset.UtcNow, string.Empty, null, Severity.High, "SEC-01", summary)
            {
                ToolKind = "shell",
                Node = "node-a",
                SessionId = "s-1",
                Source = "claude-code",
            },
            CancellationToken.None);
    }

    private Dictionary<string, string?> Env(string audit) => new(StringComparer.Ordinal)
    {
        [ResidentSettings.EnableVariable] = "on",
        [ResidentSettings.DirectoryVariable] = _dir,
        ["SENTINEL_HOOK_SERVER_URL"] = "https://sentinel.example.com",
        ["SENTINEL_HOOK_OIDC_ISSUER"] = "https://login.example.com",
        ["SENTINEL_HOOK_OIDC_CLIENT_ID"] = "plugin",
        ["SENTINEL_HOOK_AUDIT_SQLITE"] = audit,
    };

    private static TokenSession SignedIn()
    {
        var signIn = new SignInSettings(new Uri("https://sentinel.example.com"), new Uri("https://login.example.com"), "plugin", "openid");
        var tokens = new TokenSession(new OidcDeviceClient(new HttpClient(), signIn, TimeProvider.System), null, TimeProvider.System);
        tokens.Set(new TokenSet("access", null, DateTimeOffset.UtcNow.AddHours(1)));
        return tokens;
    }

    [Fact]
    public async Task With_a_server_a_sign_in_and_the_audit_on_the_forwarder_posts_to_the_ingest_endpoint_with_the_token()
    {
        var env = Env(_db);
        var settings = ResidentSettings.FromEnvironment(env)!;
        ResidentState.Open(settings).WritePinnedKeys("acme", PinnedProfileKeys.Create([ProfileSigningKey.Generate().PublicKey]));
        await AppendAsync("first");
        using var recording = new RecordingHandler(_server);

        var forwarder = EventForwarding.Open(env, settings, SignedIn(), recording, TextWriter.Null);
        var result = await forwarder!.ForwardAsync(CancellationToken.None);

        Assert.Equal(1, result.Sent);
        Assert.False(result.Failed);
        Assert.Equal(Endpoint, recording.Uri);
        Assert.Equal("Bearer access", recording.Authorization);
        Assert.Equal("acme", _server.Batches[0].GetProperty("organisation").GetString());
    }

    [Fact]
    public void With_the_local_audit_off_there_is_nothing_to_forward_and_no_forwarder()
    {
        var env = Env("off");

        Assert.Null(EventForwarding.Open(env, ResidentSettings.FromEnvironment(env)!, SignedIn(), inner: null, TextWriter.Null));
    }

    [Fact]
    public async Task A_cursor_that_cannot_be_stored_fails_the_pass_and_sends_nothing()
    {
        // A directory where the cursor file belongs can be neither read nor replaced.
        Directory.CreateDirectory(Path.Combine(_dir, EventCursor.FileName));
        await AppendAsync("first");
        var log = new List<string>();
        var forwarder = new EventForwarder(
            new SqliteAuditSource(_db), new EventCursor(_dir), new HttpClient(_server), Endpoint, () => "acme", _ => false, log.Add);

        var result = await forwarder.ForwardAsync(CancellationToken.None);

        Assert.True(result.Failed);
        Assert.Equal(0, result.Sent);
        Assert.Empty(_server.Batches);
        Assert.Contains(log, line => line.StartsWith("the event cursor could not be stored", StringComparison.Ordinal));
    }

    [Fact]
    public void A_cursor_file_that_does_not_hold_a_sequence_reads_as_no_cursor()
    {
        PolicyCache.Write(Path.Combine(_dir, EventCursor.FileName), Encoding.UTF8.GetBytes("not json"));

        Assert.Null(new EventCursor(_dir).Read());
    }

    [Fact]
    public void An_unreadable_node_map_routes_no_events()
    {
        var root = RepositoryTestSupport.NewDir();
        try
        {
            var env = Env(_db);
            var state = ResidentState.Open(ResidentSettings.FromEnvironment(env)!);
            state.WriteNodeMap(new NodeMap([new("github.com/acme/owned", "node-a")]));
            var owned = RepositoryTestSupport.Repo(root, "owned", "git@github.com:acme/owned.git");
            Assert.NotNull(EventRouting.Resolve(env, PolicyClis.ClaudeCode, "Bash", owned));

            File.WriteAllText(Path.Combine(state.Directory, ResidentState.NodesFile), "damaged");

            Assert.Null(EventRouting.Resolve(env, PolicyClis.ClaudeCode, "Bash", owned));
        }
        finally
        {
            RepositoryTestSupport.Delete(root);
        }
    }

    /// <summary>Records the address and the token of the request, then lets the stub answer it.</summary>
    private sealed class RecordingHandler(HttpMessageHandler inner) : DelegatingHandler(inner)
    {
        public Uri? Uri { get; private set; }

        public string? Authorization { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Uri = request.RequestUri;
            Authorization = request.Headers.Authorization?.ToString();
            return base.SendAsync(request, cancellationToken);
        }
    }
}
