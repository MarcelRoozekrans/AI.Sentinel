using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using AI.Sentinel.Approvals;
using AI.Sentinel.Approvals.Configuration;
using AI.Sentinel.AspNetCore;
using AI.Sentinel.AspNetCore.AdminAudit;
using AI.Sentinel.AspNetCore.PolicyFolder;
using AI.Sentinel.AspNetCore.ServerApprovals;
using AI.Sentinel.Authorization;
using AI.Sentinel.ClaudeCode.ServerApprovals;
using AI.Sentinel.Profiles;
using AI.Sentinel.Tests.AspNetCore;
using AI.Sentinel.Tests.AspNetCore.PolicyFolder;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Xunit;
using ZeroAlloc.Authorization;
using static AI.Sentinel.Tests.AspNetCore.PolicyFolder.PolicyFolderFixture;

namespace AI.Sentinel.Tests.ServerApprovals;

/// <summary>The approval store that goes through the server (#662): the endpoints of the server part, the client that asks them, and the
/// <c>http</c> backend of the hook.</summary>
[Collection("NonParallel")]
public sealed partial class HttpApprovalStoreTests : IAsyncDisposable
{
    private const string TwoTeams = """
        {
          "organisation": "acme",
          "nodes": [
            {"id": "acme", "kind": "organisation"},
            {"id": "team-a", "kind": "team"},
            {"id": "team-b", "kind": "team"}
          ],
          "repositories": {"github.com/acme/widgets": "team-a", "github.com/acme/gadgets": "team-b"},
          "roles": [
            {"group": "sec", "role": "administrator", "node": "acme"},
            {"group": "leads-a", "role": "team_lead", "node": "team-a"},
            {"group": "leads-b", "role": "team_lead", "node": "team-b"}
          ]
        }
        """;

    private const string Gadgets = "github.com/acme/gadgets";
    private const string Path = "/ai-sentinel/approvals";

    private readonly PolicyFolderFixture _folder = new();
    private readonly SettableTime _time = new(AdminAuditTestSupport.T0);
    private IHost? _host;
    private ServerApprovalStore? _store;

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public async ValueTask DisposeAsync()
    {
        if (_host is not null)
        {
            await _host.StopAsync(Ct);
            _host.Dispose();
        }

        _folder.Dispose();
    }

    // ---- the server -------------------------------------------------------------------------------------------------------

    private async Task StartAsync()
    {
        var seed = Ed25519Crypto.NewSeed();
        _folder.Write("v1", nodes: TwoTeams);
        _folder.LinkTo("v1");
        _store = new ServerApprovalStore(_time);
        _host = await new HostBuilder()
            .ConfigureWebHost(web =>
            {
                web.UseTestServer();
                web.ConfigureServices(s =>
                {
                    s.AddRouting();
                    s.AddAuthorization(o => o.AddPolicy("AISentinelDeveloper", p => p.RequireAssertion(_ => true)));
                    s.AddSingleton<IReadOnlyList<AI.Sentinel.ClaudeCode.Policy.Rego.IRegoCompiler>>([_folder.Compiler]);
                    s.AddAISentinelAdminAudit(o => o.SigningKey = Convert.ToBase64String(seed));
                    s.AddAISentinelPolicyFolder(o =>
                    {
                        o.Path = _folder.Folder;
                        o.SigningKey = Convert.ToBase64String(seed);
                        o.SettleDelay = TimeSpan.FromMilliseconds(10);
                        o.PollInterval = TimeSpan.FromMilliseconds(100);
                    });
                    s.AddSingleton(_store);
                    s.AddAISentinelApprovalServer();
                });
                web.Configure(app =>
                {
                    app.Use(async (ctx, next) =>
                    {
                        if (ctx.Request.Headers.TryGetValue("X-User", out var user))
                        {
                            var groups = ctx.Request.Headers["X-Group"].Select(g => new Claim("groups", g!));
                            ctx.User = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", user.ToString()), .. groups], "test"));
                        }

                        await next();
                    });
                    app.UseRouting();
                    app.UseEndpoints(e => e.MapAISentinelApprovalServer());
                });
            })
            .StartAsync(Ct);
        var loader = _host.Services.GetRequiredService<PolicyFolderLoader>();
        var deadline = DateTime.UtcNow.AddSeconds(20);
        while (loader.Current is null && DateTime.UtcNow < deadline)
        {
            await Task.Delay(20, Ct);
        }

        Assert.NotNull(loader.Current);
    }

    private HttpClient Client(string? user, params string[] groups)
    {
        var client = _host!.GetTestServer().CreateClient();
        if (user is not null)
        {
            client.DefaultRequestHeaders.Add("X-User", user);
            foreach (var group in groups)
            {
                client.DefaultRequestHeaders.Add("X-Group", group);
            }
        }

        return client;
    }

    private HttpClient Dave() => Client("dave", "nobody");

    private HttpClient Lena() => Client("lena", "leads-a");

    private HttpClient Liam() => Client("liam", "leads-b");

    private HttpClient Root() => Client("root", "sec");

    // ---- the hook ---------------------------------------------------------------------------------------------------------

    private sealed class Caller(string id) : ISecurityContext
    {
        public string Id { get; } = id;
        public IReadOnlySet<string> Roles { get; } = new HashSet<string>(StringComparer.Ordinal);
        public IReadOnlyDictionary<string, string> Claims { get; } = new Dictionary<string, string>(StringComparer.Ordinal);
    }

    private static ApprovalSpec Spec(string policy = "approval:Bash", TimeSpan? grant = null) =>
        new() { PolicyName = policy, GrantDuration = grant ?? TimeSpan.FromMinutes(15) };

    private static ApprovalContext Context(string json = """{"command":"rm -rf build"}""") =>
        new("Bash", JsonDocument.Parse(json).RootElement.Clone(), "clean the build");

    private static HttpApprovalStore HookOf(IApprovalChannel? channel, string repository = Repository, Func<JsonElement, JsonElement?>? redact = null) =>
        new(channel, redact ?? (args => args), repository, pollInterval: TimeSpan.FromMilliseconds(10));

    private HttpApprovalStore HookOf(HttpClient client, string repository = Repository, Func<JsonElement, JsonElement?>? redact = null) =>
        HookOf(new ApprovalServerClient(client), repository, redact);

    private static async Task<ApprovalState.Pending> OpenAsync(HttpApprovalStore hook, string policy = "approval:Bash") =>
        Assert.IsType<ApprovalState.Pending>(await hook.EnsureRequestAsync(new Caller("hook"), Spec(policy), Context(), Ct));

    private static async Task<HttpResponseMessage> DecideAsync(HttpClient approver, string id, string verb, string? body = null) =>
        await approver.PostAsync($"{Path}/{id}/{verb}", body is null ? null : new StringContent(body, Encoding.UTF8, "application/json"), Ct);

    // ---- acceptance: approve and deny over HTTP -----------------------------------------------------------------------------

    [Fact]
    public async Task An_approval_raised_by_a_hook_is_listed_and_approved_over_http_and_the_hook_acts_on_it_when_the_agent_retries()
    {
        await StartAsync();
        var hook = HookOf(Dave());

        var pending = await OpenAsync(hook);
        Assert.True(pending.IsNew);
        Assert.Equal("clean the build", (await hook.EnsureRequestAsync(new Caller("hook"), Spec(), Context(), Ct) as ApprovalState.Pending)?.Reason ?? "clean the build");

        // The agent retries while the request is open: the same request, not a new one.
        var again = Assert.IsType<ApprovalState.Pending>(await hook.EnsureRequestAsync(new Caller("hook"), Spec(), Context(), Ct));
        Assert.Equal(pending.RequestId, again.RequestId);
        Assert.False(again.IsNew);

        var listed = await Lena().GetFromJsonAsync(Path, ApprovalWireJsonContext.Default.ApprovalListWire, Ct);
        var item = Assert.Single(listed!.Requests);
        Assert.Equal(pending.RequestId, item.Id);
        Assert.Equal("dave", item.Requester);
        Assert.Equal("Bash", item.Tool);

        Assert.Equal(HttpStatusCode.OK, (await DecideAsync(Lena(), pending.RequestId, "approve", """{"note":"fine"}""")).StatusCode);

        var granted = Assert.IsType<ApprovalState.Active>(await hook.EnsureRequestAsync(new Caller("hook"), Spec(), Context(), Ct));
        Assert.Equal(pending.RequestId, granted.RequestId);
        Assert.True(granted.ExpiresAt > _time.Now.AddMinutes(14));
        Assert.Empty((await Lena().GetFromJsonAsync(Path, ApprovalWireJsonContext.Default.ApprovalListWire, Ct))!.Requests);
    }

    [Fact]
    public async Task A_denial_over_http_is_acted_on_the_same_way()
    {
        await StartAsync();
        var hook = HookOf(Dave());
        var pending = await OpenAsync(hook);

        Assert.Equal(HttpStatusCode.OK, (await DecideAsync(Lena(), pending.RequestId, "deny", """{"reason":"not on a Friday"}""")).StatusCode);

        var denied = Assert.IsType<ApprovalState.Denied>(await hook.EnsureRequestAsync(new Caller("hook"), Spec(), Context(), Ct));
        Assert.Equal("not on a Friday", denied.Reason);
        Assert.Equal(pending.RequestId, denied.RequestId);

        // The denial is seen once; the next call opens a new request.
        var next = Assert.IsType<ApprovalState.Pending>(await hook.EnsureRequestAsync(new Caller("hook"), Spec(), Context(), Ct));
        Assert.NotEqual(pending.RequestId, next.RequestId, StringComparer.Ordinal);
    }

    [Fact]
    public async Task An_approval_that_ran_out_is_denied_as_expired_once_and_then_asked_again()
    {
        await StartAsync();
        var hook = HookOf(Dave());
        var pending = await OpenAsync(hook);
        await DecideAsync(Lena(), pending.RequestId, "approve");
        _time.Now = _time.Now.AddMinutes(16);

        var expired = Assert.IsType<ApprovalState.Denied>(await hook.EnsureRequestAsync(new Caller("hook"), Spec(), Context(), Ct));
        Assert.Equal("expired", expired.Reason);
        Assert.IsType<ApprovalState.Pending>(await hook.EnsureRequestAsync(new Caller("hook"), Spec(), Context(), Ct));
    }

    [Fact]
    public async Task Waiting_for_a_decision_returns_when_the_request_is_decided()
    {
        await StartAsync();
        var hook = HookOf(Dave());
        var pending = await OpenAsync(hook);
        var waiting = hook.WaitForDecisionAsync(pending.RequestId, TimeSpan.FromSeconds(20), Ct).AsTask();

        await DecideAsync(Lena(), pending.RequestId, "approve");

        Assert.IsType<ApprovalState.Active>(await waiting.WaitAsync(TimeSpan.FromSeconds(20), Ct));
    }

    [Fact]
    public async Task Waiting_for_a_decision_that_does_not_come_returns_the_pending_state()
    {
        await StartAsync();
        var hook = HookOf(Dave());
        var pending = await OpenAsync(hook);

        var state = await hook.WaitForDecisionAsync(pending.RequestId, TimeSpan.Zero, Ct);

        Assert.Equal(pending.RequestId, Assert.IsType<ApprovalState.Pending>(state).RequestId);
    }

    // ---- acceptance: deny until a grant exists, and when the server is unreachable ------------------------------------------

    private static DefaultToolCallGuard Guard() =>
        new([], new Dictionary<string, IAuthorizationPolicy>(StringComparer.Ordinal), ToolPolicyDefault.Allow, approvalStore: null, logger: null);

    [Fact]
    public async Task Until_a_grant_exists_the_call_is_denied_with_a_message_that_it_waits_for_approval()
    {
        await StartAsync();
        var decision = await Guard().EvaluateApprovalAsync(new Caller("hook"), "Bash", Context().Args, Spec(), HookOf(Dave()), Ct);

        var required = Assert.IsType<AuthorizationDecision.RequireApprovalDecision>(decision);
        var message = ApprovalReceipt.Format("Bash", required);
        Assert.Contains("Approval required to invoke tool 'Bash'", message, StringComparison.Ordinal);
        Assert.Contains($"{Path}/{required.RequestId}", message, StringComparison.Ordinal);
        Assert.Contains("retry the tool call", message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task While_the_server_is_unreachable_the_call_is_denied_with_a_message_that_the_server_is_unreachable()
    {
        using var down = new HttpClient(new ThrowingHandler()) { BaseAddress = new Uri("https://sentinel.example.com/") };

        var decision = await Guard().EvaluateApprovalAsync(new Caller("hook"), "Bash", Context().Args, Spec(), HookOf(down), Ct);

        var denied = Assert.IsType<AuthorizationDecision.DenyDecision>(decision);
        Assert.Contains("unreachable", denied.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_server_that_answers_an_error_or_nonsense_is_unreachable_too()
    {
        foreach (var handler in new HttpMessageHandler[] { new StatusHandler(HttpStatusCode.InternalServerError), new StatusHandler(HttpStatusCode.ServiceUnavailable), new StatusHandler(HttpStatusCode.OK, "not json") })
        {
            using var client = new HttpClient(handler) { BaseAddress = new Uri("https://sentinel.example.com/") };
            var state = await HookOf(client).EnsureRequestAsync(new Caller("hook"), Spec(), Context(), Ct);

            Assert.Equal(HttpApprovalStore.UnreachableReason, Assert.IsType<ApprovalState.Denied>(state).Reason);
        }
    }

    [Fact]
    public async Task A_developer_who_is_not_signed_in_is_denied_with_a_message_that_says_so()
    {
        await StartAsync();

        var state = await HookOf(Client(user: null)).EnsureRequestAsync(new Caller("hook"), Spec(), Context(), Ct);

        Assert.Equal(HttpApprovalStore.SignInNeededReason, Assert.IsType<ApprovalState.Denied>(state).Reason);
    }

    [Fact]
    public async Task A_hook_without_a_channel_denies_as_unreachable_and_asks_nobody()
    {
        var state = await HookOf(channel: null).EnsureRequestAsync(new Caller("hook"), Spec(), Context(), Ct);
        var wait = await HookOf(channel: null).WaitForDecisionAsync("req-1", TimeSpan.Zero, Ct);

        Assert.Equal(HttpApprovalStore.OffReason, Assert.IsType<ApprovalState.Denied>(state).Reason);
        Assert.Contains("unreachable", HttpApprovalStore.OffReason, StringComparison.Ordinal);
        Assert.IsType<ApprovalState.Denied>(wait);
    }

    // ---- acceptance: who may decide -----------------------------------------------------------------------------------------

    [Fact]
    public async Task Nobody_approves_or_denies_their_own_request_whatever_their_role()
    {
        await StartAsync();
        foreach (var (name, groups) in new[] { ("lena", "leads-a"), ("root", "sec") })
        {
            var own = Client(name, groups);
            var pending = await OpenAsync(HookOf(own), $"approval:{name}");

            Assert.Equal(HttpStatusCode.Forbidden, (await DecideAsync(own, pending.RequestId, "approve")).StatusCode);
            Assert.Equal(HttpStatusCode.Forbidden, (await DecideAsync(own, pending.RequestId, "deny")).StatusCode);
            Assert.IsType<ApprovalState.Pending>(await HookOf(own).EnsureRequestAsync(new Caller("hook"), Spec($"approval:{name}"), Context(), Ct));
            Assert.DoesNotContain((await own.GetFromJsonAsync(Path, ApprovalWireJsonContext.Default.ApprovalListWire, Ct))!.Requests, r => string.Equals(r.Id, pending.RequestId, StringComparison.Ordinal));
        }
    }

    [Fact]
    public async Task A_team_lead_decides_only_for_repositories_on_their_node()
    {
        await StartAsync();
        var pending = await OpenAsync(HookOf(Dave()));

        // The lead of another team, and a developer, do not even see the request.
        Assert.Equal(HttpStatusCode.NotFound, (await DecideAsync(Liam(), pending.RequestId, "approve")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await DecideAsync(Client("erin", "nobody"), pending.RequestId, "approve")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await Liam().GetAsync($"{Path}/{pending.RequestId}", Ct)).StatusCode);
        Assert.Empty((await Liam().GetFromJsonAsync(Path, ApprovalWireJsonContext.Default.ApprovalListWire, Ct))!.Requests);
        Assert.IsType<ApprovalState.Pending>(await HookOf(Dave()).EnsureRequestAsync(new Caller("hook"), Spec(), Context(), Ct));

        Assert.Equal(HttpStatusCode.OK, (await DecideAsync(Lena(), pending.RequestId, "approve")).StatusCode);
    }

    [Fact]
    public async Task An_administrator_decides_on_every_node_and_a_repository_that_no_node_owns_is_theirs_alone()
    {
        await StartAsync();
        var gadgets = await OpenAsync(HookOf(Dave(), Gadgets), "approval:gadgets");
        var unowned = await OpenAsync(HookOf(Dave(), "github.com/else/where"), "approval:unowned");

        Assert.Equal(HttpStatusCode.NotFound, (await DecideAsync(Lena(), unowned.RequestId, "approve")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await DecideAsync(Root(), gadgets.RequestId, "deny")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await DecideAsync(Root(), unowned.RequestId, "approve")).StatusCode);
    }

    [Fact]
    public async Task A_request_that_is_decided_cannot_be_decided_again()
    {
        await StartAsync();
        var pending = await OpenAsync(HookOf(Dave()));

        Assert.Equal(HttpStatusCode.OK, (await DecideAsync(Lena(), pending.RequestId, "deny")).StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, (await DecideAsync(Root(), pending.RequestId, "approve")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await DecideAsync(Root(), "req-unknown", "approve")).StatusCode);
    }

    [Fact]
    public async Task A_requester_reads_their_own_requests_and_nobody_else_does()
    {
        await StartAsync();
        var pending = await OpenAsync(HookOf(Dave()));

        var own = await Dave().GetFromJsonAsync(Path + "?mine=true", ApprovalWireJsonContext.Default.ApprovalListWire, Ct);
        Assert.Equal(pending.RequestId, Assert.Single(own!.Requests).Id);
        Assert.Equal(HttpStatusCode.OK, (await Dave().GetAsync($"{Path}/{pending.RequestId}", Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await Client("erin", "nobody").GetAsync($"{Path}/{pending.RequestId}", Ct)).StatusCode);
        Assert.Empty((await Dave().GetFromJsonAsync(Path, ApprovalWireJsonContext.Default.ApprovalListWire, Ct))!.Requests);
    }

    [Fact]
    public async Task The_endpoints_refuse_what_is_not_a_request()
    {
        await StartAsync();
        var anonymous = Client(user: null);

        Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.GetAsync(Path, Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await Dave().PostAsync(Path, new StringContent("{}", Encoding.UTF8, "application/json"), Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await Dave().PostAsync(Path, new StringContent("nope", Encoding.UTF8, "application/json"), Ct)).StatusCode);
        var tooLarge = new StringContent(new string('x', ApprovalEndpointsLimit + 1), Encoding.UTF8, "application/json");
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, (await Dave().PostAsync(Path, tooLarge, Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await Dave().GetAsync($"{Path}/req-unknown", Ct)).StatusCode);
    }

    private const int ApprovalEndpointsLimit = ApprovalEndpoints.MaxBodyBytes;

    // ---- acceptance: the audit log --------------------------------------------------------------------------------------------

    [Fact]
    public async Task Each_approve_and_deny_is_written_to_the_audit_log_with_its_channel_and_a_refused_one_is_not()
    {
        await StartAsync();
        var approved = await OpenAsync(HookOf(Dave()), "approval:one");
        var denied = await OpenAsync(HookOf(Dave()), "approval:two");

        await DecideAsync(Liam(), approved.RequestId, "approve");
        await DecideAsync(Dave(), approved.RequestId, "approve");
        await DecideAsync(Lena(), approved.RequestId, "approve");
        await DecideAsync(Root(), denied.RequestId, "deny", """{"reason":"no"}""");
        await DecideAsync(Root(), denied.RequestId, "deny");

        var entries = await _host!.Services.GetRequiredService<IAdminAuditStore>().ReadAsync(Organisation, Ct);
        Assert.Collection(
            entries.Where(e => string.Equals(e.Channel, AdminAuditNames.Of(AdminAuditChannel.Web), StringComparison.Ordinal)),
            e => AssertEntry(e, "approve", "lena", approved.RequestId),
            e => AssertEntry(e, "deny", "root", denied.RequestId));
    }

    private static void AssertEntry(AdminAuditEntry entry, string action, string actor, string target)
    {
        Assert.Equal(action, entry.Action);
        Assert.Equal(actor, entry.Actor);
        Assert.Equal(target, entry.Target);
        Assert.Equal(AdminAuditNames.Of(AdminAuditChannel.Web), entry.Channel);
        Assert.Equal(Organisation, entry.Organisation);
    }

    // ---- acceptance: the tool input and its retention ---------------------------------------------------------------------------

    [Fact]
    public async Task An_approval_request_carries_the_tool_input_after_redaction_so_the_approver_sees_what_they_approve()
    {
        await StartAsync();
        await using var provider = AI.Sentinel.ClaudeCode.Cli.Program.BuildProvider(embeddingGenerator: null, approvalConfig: null);
        var hook = HookOf(Dave(), redact: args => ApprovalArgsRedaction.Redact(provider, args));

        var context = new ApprovalContext("Bash", JsonDocument.Parse("""{"command":"mail alice.private@example.com the build log"}""").RootElement.Clone(), null);
        var pending = Assert.IsType<ApprovalState.Pending>(await hook.EnsureRequestAsync(new Caller("hook"), Spec(), context, Ct));

        var item = Assert.Single((await Lena().GetFromJsonAsync(Path, ApprovalWireJsonContext.Default.ApprovalListWire, Ct))!.Requests);
        Assert.Equal(pending.RequestId, item.Id);
        var command = item.Args!.Value.GetProperty("command").GetString()!;
        Assert.DoesNotContain("alice.private@example.com", command, StringComparison.Ordinal);
        Assert.Contains("mail ", command, StringComparison.Ordinal);
        Assert.Contains("the build log", command, StringComparison.Ordinal);
        Assert.Contains("[EMAIL_", command, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_tool_input_that_cannot_be_redacted_is_withheld_and_never_sent()
    {
        await StartAsync();
        var hook = HookOf(Dave(), redact: _ => null);

        await hook.EnsureRequestAsync(new Caller("hook"), Spec(), Context("""{"command":"secret-token-123"}"""), Ct);

        var item = Assert.Single((await Lena().GetFromJsonAsync(Path, ApprovalWireJsonContext.Default.ApprovalListWire, Ct))!.Requests);
        Assert.Equal(HttpApprovalStore.WithheldInput, item.Args!.Value.GetString());
        Assert.DoesNotContain("secret-token-123", JsonSerializer.Serialize(item, ApprovalWireJsonContext.Default.ApprovalListItemWire), StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_request_is_deleted_thirty_days_after_it_is_decided_and_a_pending_one_is_kept()
    {
        await StartAsync();
        var decided = await OpenAsync(HookOf(Dave()), "approval:decided");
        var waiting = await OpenAsync(HookOf(Dave()), "approval:waiting");
        await DecideAsync(Lena(), decided.RequestId, "approve");

        _time.Now += ServerApprovalStore.Retention - TimeSpan.FromMinutes(1);
        Assert.Equal(HttpStatusCode.OK, (await Lena().GetAsync($"{Path}/{decided.RequestId}", Ct)).StatusCode);

        _time.Now += TimeSpan.FromMinutes(2);
        Assert.Equal(HttpStatusCode.NotFound, (await Lena().GetAsync($"{Path}/{decided.RequestId}", Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await Lena().GetAsync($"{Path}/{waiting.RequestId}", Ct)).StatusCode);
        Assert.Equal(TimeSpan.FromDays(30), ServerApprovalStore.Retention);
    }

    [Fact]
    public async Task A_decided_request_is_deleted_by_the_retention_service_without_any_call_to_the_store()
    {
        await StartAsync();
        var decided = await OpenAsync(HookOf(Dave()), "approval:decided");
        var waiting = await OpenAsync(HookOf(Dave()), "approval:waiting");
        await DecideAsync(Lena(), decided.RequestId, "approve");
        using var service = new ServerApprovalRetentionService(_store!, _time, TimeSpan.FromMilliseconds(20));
        await service.StartAsync(Ct);
        try
        {
            _time.Now += ServerApprovalStore.Retention + TimeSpan.FromMinutes(1);
            var deadline = DateTime.UtcNow.AddSeconds(20);
            while (_store!.Count > 1 && DateTime.UtcNow < deadline)
            {
                await Task.Delay(20, Ct);
            }

            Assert.Equal(1, _store.Count);
            Assert.NotNull(_store.Find(waiting.RequestId));
        }
        finally
        {
            await service.StopAsync(Ct);
        }
    }

    [Fact]
    public async Task The_same_rule_in_another_repository_is_a_request_of_its_own_and_does_not_reuse_an_approval()
    {
        await StartAsync();
        var widgets = await OpenAsync(HookOf(Dave()));
        await DecideAsync(Lena(), widgets.RequestId, "approve");

        var gadgets = Assert.IsType<ApprovalState.Pending>(await HookOf(Dave(), Gadgets).EnsureRequestAsync(new Caller("hook"), Spec(), Context(), Ct));

        Assert.True(gadgets.IsNew);
        Assert.False(string.Equals(widgets.RequestId, gadgets.RequestId, StringComparison.Ordinal));
    }

    [Fact]
    public async Task Waiting_for_a_decision_lasts_the_whole_timeout_even_when_it_is_shorter_than_a_poll_interval()
    {
        var channel = new PendingChannel();
        var hook = new HttpApprovalStore(channel, args => args, Repository, pollInterval: TimeSpan.FromSeconds(30));
        var started = DateTime.UtcNow;

        var state = await hook.WaitForDecisionAsync("req-1", TimeSpan.FromMilliseconds(300), Ct);

        Assert.IsType<ApprovalState.Pending>(state);
        Assert.True(DateTime.UtcNow - started >= TimeSpan.FromMilliseconds(250));
        Assert.Equal(2, channel.Gets);
    }

    private sealed class PendingChannel : IApprovalChannel
    {
        public int Gets { get; private set; }

        public Task<ApprovalChannelReply> EnsureAsync(ApprovalRequestWire request, CancellationToken ct) => throw new NotSupportedException();

        public Task<ApprovalChannelReply> GetAsync(string requestId, CancellationToken ct)
        {
            Gets++;
            return Task.FromResult(new ApprovalChannelReply(
                ApprovalChannelStatus.Ok, new ApprovalStateWire { Id = requestId, State = ApprovalWireStates.Pending }));
        }
    }

    // ---- the backend of the approval config -------------------------------------------------------------------------------------

    [Fact]
    public void The_http_backend_is_a_backend_of_the_approval_config_and_the_others_are_as_before()
    {
        var config = ApprovalConfigLoader.Parse(JsonDocument.Parse("""{"backend":"http","tools":{"Bash":{"role":"Ops"}}}""").RootElement);

        Assert.Equal(ApprovalBackendKind.Http, ApprovalBackendSelector.GetBackend(config));
        Assert.Equal(ApprovalBackendKind.Sqlite, ApprovalBackendSelector.GetBackend(
            ApprovalConfigLoader.Parse(JsonDocument.Parse("""{"backend":"sqlite","databasePath":"a.db"}""").RootElement)));
        Assert.Throws<InvalidOperationException>(() => ApprovalConfigLoader.Parse(JsonDocument.Parse("""{"backend":"ftp"}""").RootElement));
    }

    private sealed class ThrowingHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            throw new HttpRequestException("no route to host");
    }

    private sealed class StatusHandler(HttpStatusCode status, string? body = null) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(status) { Content = new StringContent(body ?? string.Empty) });
    }
}
