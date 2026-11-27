using System.Diagnostics;
using System.Net;
using System.Text.Json;
using AI.Sentinel.ClaudeCode;
using AI.Sentinel.ClaudeCode.Resident;
using AI.Sentinel.Profiles;
using AI.Sentinel.Tests.AspNetCore.PolicyFolder;
using AI.Sentinel.Tests.ClaudeCode.Policy;
using AI.Sentinel.Tests.ClaudeCode.Resident;
using Xunit;
using static AI.Sentinel.Tests.AspNetCore.SessionControl.SessionControlTestHost;

namespace AI.Sentinel.Tests.AspNetCore.SessionControl;

public sealed class SessionPauseTests : IDisposable
{
    private static readonly TimeSpan Fast = TimeSpan.FromMilliseconds(20);

    private readonly PolicyFolderFixture _folder = new();
    private readonly byte[] _seed = Ed25519Crypto.NewSeed();
    private readonly string _dir = ResidentTestSupport.NewDir();

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public void Dispose()
    {
        _folder.Dispose();
        ResidentTestSupport.Delete(_dir);
    }

    private Task<SessionControlTestHost> StartAsync(TimeSpan? heartbeat = null) => SessionControlTestHost.StartAsync(_folder, _seed, heartbeat, ct: Ct);

    private ResidentState State() => new(ResidentPaths.Prepare(new ResidentSettings(_dir, ResidentSettings.DefaultIdleTimeout, ResidentSettings.DefaultBudget)));

    private static ServerLinkTiming ShortTiming => new(
        TimeSpan.FromMilliseconds(30), TimeSpan.FromMilliseconds(100), TimeSpan.FromSeconds(10),
        TimeSpan.FromMilliseconds(30), TimeSpan.FromMilliseconds(100), TimeSpan.FromMilliseconds(200), TimeSpan.FromDays(1));

    // The link of a developer's resident process to the test server, with what it needs and no more.
    private sealed class Link : IAsyncDisposable
    {
        private readonly CancellationTokenSource _stop = new();
        private readonly HttpClient _http;
        private readonly Task _run;

        public Link(SessionControlTestHost host, ResidentState state, HttpMessageHandler? handler = null)
        {
            Board = new PauseBoard(state);
            Service = new ResidentService(null, null, Board);
            _http = new HttpClient(handler ?? new SignedInHandler(host.Handler));
            var refresher = new ProfileRefresher(state, _http, new Uri("http://localhost"), Service, ShortTiming, TimeProvider.System);
            var link = new ServerLink(_http, new Uri("http://localhost"), Board, refresher, ShortTiming, TimeProvider.System);
            _run = Task.Run(() => link.RunAsync(_stop.Token));
        }

        public PauseBoard Board { get; }

        public ResidentService Service { get; }

        public async ValueTask DisposeAsync()
        {
            await _stop.CancelAsync();
            await _run.WaitAsync(TimeSpan.FromSeconds(10));
            _http.Dispose();
            Service.Dispose();
            _stop.Dispose();
        }
    }

    private static async Task WaitForAsync(Func<bool> condition, string what, int seconds = 10)
    {
        var deadline = DateTime.UtcNow.AddSeconds(seconds);
        while (!condition())
        {
            if (DateTime.UtcNow > deadline)
            {
                throw new TimeoutException("timed out waiting for " + what);
            }

            await Task.Delay(5, Ct);
        }
    }

    [Fact]
    public async Task A_team_lead_pauses_and_releases_a_session_of_their_node_and_both_are_written_to_the_audit_log()
    {
        await using var host = await StartAsync();

        var paused = await host.PauseAsync("s-1", "alice", "leads-a", Widgets, "incident review", Ct);
        var released = await host.ReleaseAsync("s-1", "alice", "leads-a", Ct);

        Assert.Equal(HttpStatusCode.OK, paused.StatusCode);
        var pause = JsonSerializer.Deserialize<JsonElement>(await paused.Content.ReadAsStringAsync(Ct));
        Assert.Equal("s-1", pause.GetProperty("session").GetString());
        Assert.Equal("incident review", pause.GetProperty("reason").GetString());
        Assert.Equal(HttpStatusCode.NoContent, released.StatusCode);
        var audit = (await _folder.AuditAsync()).Where(e => e.Action is "pause" or "release").ToList();
        Assert.Equal([("pause", "alice", "s-1", "web"), ("release", "alice", "s-1", "web")], audit.Select(e => (e.Action, e.Actor, e.Target, e.Channel)));
    }

    [Fact]
    public async Task A_developer_a_team_lead_of_another_node_and_an_anonymous_caller_cannot_pause()
    {
        await using var host = await StartAsync();

        var developer = await host.PauseAsync("s-1", "dave", "", Widgets, ct: Ct);
        var otherTeam = await host.PauseAsync("s-1", "bob", "leads-b", Widgets, ct: Ct);
        var anonymous = await host.Client.SendAsync(Request(HttpMethod.Post, "/ai-sentinel/sessions/s-1/pause", json: PauseBody(Widgets)), Ct);

        Assert.Equal(HttpStatusCode.Forbidden, developer.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, otherTeam.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);
        Assert.DoesNotContain(await _folder.AuditAsync(), e => e.Action is "pause");
        var list = await host.Client.SendAsync(Request(HttpMethod.Get, "/ai-sentinel/sessions", "root", "sec"), Ct);
        Assert.Equal("[]", await list.Content.ReadAsStringAsync(Ct));
    }

    [Fact]
    public async Task An_administrator_pauses_a_session_of_any_node_and_of_a_repository_no_node_owns_and_a_team_lead_may_not_do_the_second()
    {
        await using var host = await StartAsync();

        var gadgets = await host.PauseAsync("s-1", "root", "sec", Gadgets, ct: Ct);
        var unowned = await host.PauseAsync("s-2", "root", "sec", "github.com/else/where", ct: Ct);
        var leadOfUnowned = await host.PauseAsync("s-3", "alice", "leads-a", "github.com/else/where", ct: Ct);

        Assert.Equal(HttpStatusCode.OK, gadgets.StatusCode);
        Assert.Equal(HttpStatusCode.OK, unowned.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, leadOfUnowned.StatusCode);
    }

    [Fact]
    public async Task A_pause_needs_a_session_id_a_repository_and_an_end_in_the_future()
    {
        await using var host = await StartAsync();

        var noRepository = await host.Client.SendAsync(Request(HttpMethod.Post, "/ai-sentinel/sessions/s-1/pause", "alice", "leads-a", "{}"), Ct);
        var notJson = await host.Client.SendAsync(Request(HttpMethod.Post, "/ai-sentinel/sessions/s-1/pause", "alice", "leads-a", "nope"), Ct);
        var past = await host.Client.SendAsync(Request(HttpMethod.Post, "/ai-sentinel/sessions/s-1/pause", "alice", "leads-a",
            PauseBody(Widgets, until: DateTimeOffset.UtcNow.AddMinutes(-1))), Ct);
        var control = await host.PauseAsync("s%0A1", "alice", "leads-a", Widgets, ct: Ct);
        var longId = await host.PauseAsync(new string('x', 300), "alice", "leads-a", Widgets, ct: Ct);

        Assert.All([noRepository, notJson, past, control, longId], r => Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode));
    }

    [Fact]
    public async Task Releasing_a_session_that_is_not_paused_is_not_found_and_only_a_lead_of_its_node_may_release()
    {
        await using var host = await StartAsync();
        _ = await host.PauseAsync("s-1", "alice", "leads-a", Widgets, ct: Ct);

        var unknown = await host.ReleaseAsync("s-9", "alice", "leads-a", Ct);
        var developer = await host.ReleaseAsync("s-1", "dave", "", Ct);
        var otherTeam = await host.ReleaseAsync("s-1", "bob", "leads-b", Ct);
        var admin = await host.ReleaseAsync("s-1", "root", "sec", Ct);

        Assert.Equal(HttpStatusCode.NotFound, unknown.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, developer.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, otherTeam.StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, admin.StatusCode);
    }

    [Fact]
    public async Task A_pause_in_force_is_replaced_only_by_someone_who_may_also_lift_it()
    {
        await using var host = await StartAsync();
        _ = await host.PauseAsync("s-1", "alice", "leads-a", Widgets, ct: Ct);

        var otherTeam = await host.PauseAsync("s-1", "bob", "leads-b", Gadgets, ct: Ct);
        var sameTeam = await host.PauseAsync("s-1", "alice", "leads-a", Widgets, "again", Ct);
        var admin = await host.PauseAsync("s-1", "root", "sec", Gadgets, ct: Ct);

        Assert.Equal(HttpStatusCode.Forbidden, otherTeam.StatusCode);
        Assert.Equal(HttpStatusCode.OK, sameTeam.StatusCode);
        Assert.Equal(HttpStatusCode.OK, admin.StatusCode);
    }

    [Fact]
    public async Task A_release_lifts_only_the_pause_the_caller_was_authorized_for()
    {
        await using var host = await StartAsync();
        _ = await host.PauseAsync("s-1", "alice", "leads-a", Widgets, ct: Ct);
        var hub = (AI.Sentinel.AspNetCore.SessionControl.SessionControlHub)host.Host.Services.GetService(typeof(AI.Sentinel.AspNetCore.SessionControl.SessionControlHub))!;
        var checkedPause = hub.Find("s-1")!;

        // Another repository's lead takes the session over between the check and the release.
        _ = hub.Pause("s-1", Gadgets, null, null, _ => true);
        var released = hub.Release(checkedPause);

        Assert.False(released);
        Assert.Equal(Gadgets, hub.Find("s-1")!.Repository);
    }

    [Fact]
    public async Task The_list_shows_a_team_lead_the_pauses_of_their_own_node_only()
    {
        await using var host = await StartAsync();
        _ = await host.PauseAsync("s-a", "root", "sec", Widgets, ct: Ct);
        _ = await host.PauseAsync("s-b", "root", "sec", Gadgets, ct: Ct);

        var list = await host.Client.SendAsync(Request(HttpMethod.Get, "/ai-sentinel/sessions", "alice", "leads-a"), Ct);

        var sessions = JsonSerializer.Deserialize<JsonElement>(await list.Content.ReadAsStringAsync(Ct)).EnumerateArray().Select(e => e.GetProperty("session").GetString());
        Assert.Equal(["s-a"], sessions, StringComparer.Ordinal);
    }

    [Fact]
    public async Task Without_a_central_product_a_team_pauses_over_http_and_the_stream_starts_with_the_snapshot_then_carries_pause_release_and_heartbeat()
    {
        await using var host = await StartAsync(heartbeat: TimeSpan.FromMilliseconds(50));
        _ = await host.PauseAsync("s-0", "alice", "leads-a", Widgets, "before", Ct);
        using var response = await host.Client.SendAsync(Request(HttpMethod.Get, Sessions + "events", "dave"), HttpCompletionOption.ResponseHeadersRead, Ct);
        await using var body = await response.Content.ReadAsStreamAsync(Ct);
        var events = SseReader.ReadAsync(body, TimeSpan.FromSeconds(10), Ct).GetAsyncEnumerator(Ct);

        var snapshot = await NextAsync(events, message => !message.IsHeartbeat);
        _ = await host.PauseAsync("s-1", "alice", "leads-a", Widgets, "incident review", Ct);
        var pause = await NextAsync(events, message => !message.IsHeartbeat);
        _ = await host.ReleaseAsync("s-1", "alice", "leads-a", Ct);
        var release = await NextAsync(events, message => !message.IsHeartbeat);
        var heartbeat = await NextAsync(events, message => message.IsHeartbeat);

        Assert.Equal("text/event-stream", response.Content.Headers.ContentType?.MediaType);
        Assert.Equal(SessionEventNames.Snapshot, snapshot.Event);
        Assert.Equal(["s-0"], JsonSerializer.Deserialize(snapshot.Data!, SessionEventJsonContext.Default.SessionSnapshot)!.Pauses.Select(p => p.Session), StringComparer.Ordinal);
        Assert.Equal(SessionEventNames.Pause, pause.Event);
        Assert.Equal("incident review", JsonSerializer.Deserialize(pause.Data!, SessionEventJsonContext.Default.PausedSession)!.Reason);
        Assert.Equal((SessionEventNames.Release, "s-1"), (release.Event, JsonSerializer.Deserialize(release.Data!, SessionEventJsonContext.Default.ReleasedSession)!.Session));
        Assert.True(heartbeat.IsHeartbeat);
        await events.DisposeAsync();
    }

    private const string Sessions = "/ai-sentinel/sessions/";

    private static async Task<SseMessage> NextAsync(IAsyncEnumerator<SseMessage> events, Func<SseMessage, bool> wanted)
    {
        while (await events.MoveNextAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10), Ct))
        {
            if (wanted(events.Current))
            {
                return events.Current;
            }
        }

        throw new InvalidOperationException("the stream ended");
    }

    [Fact]
    public async Task The_stream_announces_each_published_configuration()
    {
        await using var host = await StartAsync();
        using var response = await host.Client.SendAsync(Request(HttpMethod.Get, Sessions + "events", "dave"), HttpCompletionOption.ResponseHeadersRead, Ct);
        await using var body = await response.Content.ReadAsStreamAsync(Ct);
        var events = SseReader.ReadAsync(body, TimeSpan.FromSeconds(10), Ct).GetAsyncEnumerator(Ct);
        var snapshot = await NextAsync(events, m => !m.IsHeartbeat);
        var first = JsonSerializer.Deserialize(snapshot.Data!, SessionEventJsonContext.Default.SessionSnapshot)!.ConfigurationVersion;

        _folder.Write("v2", orgRules: PolicyFolderFixture.OrgRules + "\n# v2\n", nodes: Nodes);
        _folder.LinkTo("v2");
        var announced = await NextAsync(events, m => string.Equals(m.Event, SessionEventNames.Configuration, StringComparison.Ordinal));

        Assert.NotNull(first);
        Assert.True(JsonSerializer.Deserialize(announced.Data!, SessionEventJsonContext.Default.ConfigurationAnnounced)!.Version > first);
        await events.DisposeAsync();
    }

    [Fact]
    public async Task A_pause_names_a_session_and_the_stream_and_the_state_folder_never_carry_the_person_who_paused_it()
    {
        await using var host = await StartAsync();
        var state = State();
        await using var link = new Link(host, state);
        await WaitForAsync(() => host.Host.Services.GetService(typeof(AI.Sentinel.AspNetCore.SessionControl.SessionControlHub)) is not null, "the hub");

        _ = await host.PauseAsync("s-1", "alice-the-lead", "leads-a", Widgets, "incident review", Ct);
        await WaitForAsync(() => state.FindPause("s-1", DateTimeOffset.UtcNow) is not null, "the pause");

        var file = await File.ReadAllTextAsync(Path.Combine(state.Directory, ResidentState.PauseFile), Ct);
        Assert.DoesNotContain("alice", file, StringComparison.Ordinal);
        Assert.DoesNotContain(Widgets, file, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_pause_takes_effect_on_the_pc_within_a_second_and_a_hook_reads_it_with_no_network_and_after_release_calls_proceed()
    {
        var state = State();
        var env = new Dictionary<string, string?>(StringComparer.Ordinal) { [ResidentSettings.EnableVariable] = "on", [ResidentSettings.DirectoryVariable] = _dir };
        var hook = ResidentSession.Open(env, _ => false)!;
        var allowed = new HookOutput { Decision = HookDecision.Allow };
        var host = await StartAsync();
        await using var link = new Link(host, state);
        await WaitForAsync(() => link.Board.Current().Count == 0 && LinkConnected(host), "the stream");

        var clock = Stopwatch.StartNew();
        _ = await host.PauseAsync("s-1", "alice", "leads-a", Widgets, "incident review", Ct);
        await WaitForAsync(() => state.FindPause("s-1", DateTimeOffset.UtcNow) is not null, "the pause");
        var paused = clock.Elapsed;

        // The server is gone: the hook decides from the state folder alone.
        await host.DisposeAsync();
        var denied = hook.ApplyPause(allowed, "s-1", DateTimeOffset.UtcNow);
        var other = hook.ApplyPause(allowed, "s-2", DateTimeOffset.UtcNow);

        Assert.True(paused < TimeSpan.FromSeconds(1), $"the pause took {paused}");
        Assert.Equal(HookDecision.Block, denied.Decision);
        Assert.Contains("team lead paused", denied.Reason, StringComparison.Ordinal);
        Assert.Contains("released", denied.Reason, StringComparison.Ordinal);
        Assert.Contains("incident review", denied.Reason, StringComparison.Ordinal);
        Assert.Same(allowed, other);
    }

    [Fact]
    public async Task A_release_lifts_the_pause_on_the_pc_within_a_second_and_the_next_call_proceeds()
    {
        var state = State();
        var hook = ResidentSession.Open(
            new Dictionary<string, string?>(StringComparer.Ordinal) { [ResidentSettings.EnableVariable] = "on", [ResidentSettings.DirectoryVariable] = _dir }, _ => false)!;
        var allowed = new HookOutput { Decision = HookDecision.Allow };
        await using var host = await StartAsync();
        await using var link = new Link(host, state);
        _ = await host.PauseAsync("s-1", "alice", "leads-a", Widgets, ct: Ct);
        await WaitForAsync(() => state.FindPause("s-1", DateTimeOffset.UtcNow) is not null, "the pause");

        var clock = Stopwatch.StartNew();
        _ = await host.ReleaseAsync("s-1", "alice", "leads-a", Ct);
        await WaitForAsync(() => state.FindPause("s-1", DateTimeOffset.UtcNow) is null, "the release");

        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(1), $"the release took {clock.Elapsed}");
        Assert.Same(allowed, hook.ApplyPause(allowed, "s-1", DateTimeOffset.UtcNow));
    }

    private static bool LinkConnected(SessionControlTestHost host) =>
        host.Host.Services.GetService(typeof(AI.Sentinel.AspNetCore.SessionControl.SessionControlHub)) is not null;

    [Fact]
    public void The_resident_process_denies_a_paused_session_in_every_decision_it_answers_and_leaves_the_others()
    {
        var state = State();
        var board = new PauseBoard(state);
        board.Add(new PausedSession("s-1", "incident review", null));
        using var service = new ResidentService(null, null, board);

        var evaluate = service.Answer(new ResidentRequest { Op = ResidentOps.Evaluate, Folder = "/nowhere", Version = "v", CacheDirectory = "/nowhere", Input = "{}", Session = "s-1" });
        var profile = service.Answer(new ResidentRequest { Op = ResidentOps.EvaluateProfile, Repository = "*", Input = "{}", Session = "s-1" });
        var other = service.Answer(new ResidentRequest { Op = ResidentOps.EvaluateProfile, Repository = "*", Input = "{}", Session = "s-2" });

        Assert.All([evaluate, profile], r =>
        {
            Assert.True(r.Ok);
            Assert.Equal("deny", r.Outcome);
            Assert.Contains("team lead paused", r.Reasons![0], StringComparison.Ordinal);
        });
        Assert.False(other.Ok);
    }

    [Fact]
    public async Task A_call_already_running_when_the_pause_arrives_completes_with_its_own_decision()
    {
        var state = State();
        var board = new PauseBoard(state);
        using var service = new ResidentService([new ChildProcessCompiler()], null, board);
        var folder = Path.Combine(_dir, "policy-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        await File.WriteAllTextAsync(Path.Combine(folder, "a.rego"), $"package sentinel\n\nimport rego.v1\n\ndeny contains \"unique {Guid.NewGuid():N}\" if input.kind == \"shell\"\n", Ct);
        var version = AI.Sentinel.ClaudeCode.Policy.Rego.PolicySources.Load(folder).Version;
        var request = new ResidentRequest
        {
            Op = ResidentOps.Evaluate,
            Folder = folder,
            Version = version,
            CacheDirectory = Path.Combine(_dir, "cache"),
            Input = """{"kind":"shell"}""",
            Session = "s-1",
        };

        // The call is past its pause check and about to evaluate when the session is paused.
        using var reached = new ManualResetEventSlim();
        using var paused = new ManualResetEventSlim();
        service.AfterPauseCheck = () =>
        {
            reached.Set();
            paused.Wait(TimeSpan.FromSeconds(30));
        };
        var running = Task.Run(() => service.Answer(request), Ct);
        Assert.True(reached.Wait(TimeSpan.FromSeconds(30), Ct));
        board.Add(new PausedSession("s-1", null, null));
        paused.Set();
        var answer = await running.WaitAsync(TimeSpan.FromSeconds(60), Ct);
        var next = service.Answer(request);

        Assert.True(answer.Ok, answer.Error);
        Assert.Equal("deny", answer.Outcome);
        Assert.DoesNotContain("team lead paused", answer.Reasons![0], StringComparison.Ordinal);
        Assert.Contains("team lead paused", next.Reasons![0], StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_stream_reconnects_after_a_drop_and_resyncs_the_pause_state_it_missed()
    {
        await using var host = await StartAsync();
        var state = State();
        var flaky = new CuttableHandler(new SignedInHandler(host.Handler));
        await using var link = new Link(host, state, flaky);
        _ = await host.PauseAsync("s-a", "alice", "leads-a", Widgets, ct: Ct);
        await WaitForAsync(() => link.Board.Find("s-a") is not null, "the first pause");

        flaky.Cut(attemptsToRefuse: 2);
        _ = await host.PauseAsync("s-b", "alice", "leads-a", Widgets, ct: Ct);
        _ = await host.ReleaseAsync("s-a", "alice", "leads-a", Ct);
        await WaitForAsync(() => link.Board.Find("s-b") is not null && link.Board.Find("s-a") is null, "the resync");

        Assert.Equal(["s-b"], state.ReadPauses().Select(p => p.Session), StringComparer.Ordinal);
        Assert.True(flaky.Connections >= 2);
        _ = Fast;
    }

    [Fact]
    public async Task The_resident_process_keeps_the_link_when_it_is_signed_in_and_a_server_is_set_and_answers_a_paused_session_with_a_deny()
    {
        await using var server = await StartAsync();
        var signIn = new AI.Sentinel.ClaudeCode.SignIn.SignInSettings(new Uri("http://localhost"), new Uri("https://idp.example.com"), "client", "openid");
        var tokens = new AI.Sentinel.ClaudeCode.SignIn.TokenSession(
            new AI.Sentinel.ClaudeCode.SignIn.OidcDeviceClient(new HttpClient(), signIn, TimeProvider.System), null, TimeProvider.System);
        tokens.Set(new AI.Sentinel.ClaudeCode.SignIn.TokenSet("access", null, DateTimeOffset.UtcNow.AddHours(1)));
        await using var host = new HostedResident(_dir, tokens: tokens, server: new ServerLinkSettings(new Uri("http://localhost"), ShortTiming, new SignedInHandler(server.Handler)));
        await host.WaitUntilListeningAsync();
        var client = new ResidentClient(host.Settings);

        _ = await server.PauseAsync("s-1", "alice", "leads-a", Widgets, "incident review", Ct);
        await WaitForAsync(() => State().FindPause("s-1", DateTimeOffset.UtcNow) is not null, "the pause on the PC");
        var answer = await client.SendAsync(new ResidentRequest { Op = ResidentOps.EvaluateProfile, Repository = "*", Input = "{}", Session = "s-1" }, TimeSpan.FromSeconds(5));

        Assert.Equal("deny", answer?.Outcome);
        _ = await server.ReleaseAsync("s-1", "alice", "leads-a", Ct);
        await WaitForAsync(() => State().FindPause("s-1", DateTimeOffset.UtcNow) is null, "the release on the PC");
    }
}
