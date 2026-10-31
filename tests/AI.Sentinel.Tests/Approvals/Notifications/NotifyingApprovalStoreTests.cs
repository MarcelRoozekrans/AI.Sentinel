using System.Diagnostics;
using System.Text.Json;
using AI.Sentinel.Approvals;
using AI.Sentinel.Approvals.Notifications;
using Microsoft.Extensions.Logging;
using Xunit;
using ZeroAlloc.Authorization;

namespace AI.Sentinel.Tests.Approvals.Notifications;

public class NotifyingApprovalStoreTests
{
    private static readonly Uri Endpoint = new("https://hooks.example.com/services/abc");

    private static ApprovalNotifierSettings Settings(
        Uri? url = null, bool includeArgs = false, Uri? dashboard = null, params (string, string)[] headers) =>
        new(url ?? Endpoint,
            headers.ToDictionary(h => h.Item1, h => h.Item2, StringComparer.OrdinalIgnoreCase),
            includeArgs,
            dashboard);

    private static ApprovalSpec Spec() => new() { PolicyName = "approval:Bash" };

    private static ApprovalContext Ctx(string argsJson = "{}") =>
        new("Bash", JsonDocument.Parse(argsJson).RootElement.Clone(), null);

    private static ISecurityContext Caller() => new TestCaller("alice");

    private sealed class TestCaller(string id) : ISecurityContext
    {
        public string Id { get; } = id;
        public IReadOnlySet<string> Roles { get; } = new HashSet<string>(StringComparer.Ordinal);
        public IReadOnlyDictionary<string, string> Claims { get; } = new Dictionary<string, string>(StringComparer.Ordinal);
    }

    private sealed class RecordingHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>>? respond = null)
        : HttpMessageHandler
    {
        public List<(HttpRequestMessage Request, string Body)> Calls { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var body = request.Content is null ? string.Empty : await request.Content.ReadAsStringAsync(cancellationToken);
            lock (Calls)
            {
                Calls.Add((request, body));
            }
            return respond is null
                ? new HttpResponseMessage(System.Net.HttpStatusCode.OK)
                : await respond(request, cancellationToken);
        }
    }

    private sealed class CapturingLogger : ILogger
    {
        public List<(LogLevel Level, string Message)> Entries { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter) =>
            Entries.Add((logLevel, formatter(state, exception) + (exception?.ToString() ?? string.Empty)));
    }

    private sealed class FixedStore(ApprovalState state) : IApprovalStore
    {
        public ValueTask<ApprovalState> EnsureRequestAsync(
            ISecurityContext caller, ApprovalSpec spec, ApprovalContext context, CancellationToken ct) => ValueTask.FromResult(state);

        public ValueTask<ApprovalState> WaitForDecisionAsync(string requestId, TimeSpan timeout, CancellationToken ct) =>
            ValueTask.FromResult(state);
    }

    private static NotifyingApprovalStore Notifier(
        IApprovalStore inner, RecordingHandler handler, ApprovalNotifierSettings? settings = null, ILogger? logger = null) =>
        new(inner, settings ?? Settings(), handler, logger);

    private static JsonElement Body(RecordingHandler handler) => JsonDocument.Parse(handler.Calls.Single().Body).RootElement;

    [Fact]
    public async Task NewRequest_PostsOnce()
    {
        var handler = new RecordingHandler();
        var store = Notifier(new InMemoryApprovalStore(), handler);
        await store.EnsureRequestAsync(Caller(), Spec(), Ctx(), TestContext.Current.CancellationToken);

        var (request, _) = Assert.Single(handler.Calls);
        Assert.Equal(HttpMethod.Post, request.Method);
        Assert.Equal(Endpoint, request.RequestUri);
        Assert.Equal("application/json", request.Content!.Headers.ContentType!.MediaType);
    }

    [Fact]
    public async Task ReusedRequest_DoesNotPost()
    {
        var handler = new RecordingHandler();
        var store = Notifier(new InMemoryApprovalStore(), handler);
        await store.EnsureRequestAsync(Caller(), Spec(), Ctx(), TestContext.Current.CancellationToken);
        await store.EnsureRequestAsync(Caller(), Spec(), Ctx(), TestContext.Current.CancellationToken);

        Assert.Single(handler.Calls);
    }

    [Fact]
    public async Task WaitForDecision_DoesNotPost()
    {
        var handler = new RecordingHandler();
        var inner = new InMemoryApprovalStore();
        var store = Notifier(inner, handler);
        var pending = (ApprovalState.Pending)await store.EnsureRequestAsync(Caller(), Spec(), Ctx(), TestContext.Current.CancellationToken);
        handler.Calls.Clear();

        var state = await store.WaitForDecisionAsync(pending.RequestId, TimeSpan.Zero, TestContext.Current.CancellationToken);

        Assert.Empty(handler.Calls);
        Assert.Equal(await inner.WaitForDecisionAsync(pending.RequestId, TimeSpan.Zero, TestContext.Current.CancellationToken), state);
    }

    [Fact]
    public async Task Payload_Fields()
    {
        var handler = new RecordingHandler();
        var store = Notifier(new InMemoryApprovalStore(), handler);
        var pending = (ApprovalState.Pending)await store.EnsureRequestAsync(Caller(), Spec(), Ctx(), TestContext.Current.CancellationToken);

        var body = Body(handler);
        Assert.Equal(pending.RequestId, body.GetProperty("requestId").GetString());
        Assert.Equal("Bash", body.GetProperty("tool").GetString());
        Assert.Equal("alice", body.GetProperty("callerId").GetString());
        Assert.Equal("approval:Bash", body.GetProperty("policy").GetString());
        Assert.Equal(pending.RequestedAt, body.GetProperty("requestedAt").GetDateTimeOffset());
        Assert.Equal($"sentinel://approve/{pending.RequestId}", body.GetProperty("approvalUrl").GetString());
        Assert.Equal("Approval needed: Bash for alice (approval:Bash).", body.GetProperty("text").GetString());
        Assert.False(body.TryGetProperty("args", out _));
        Assert.False(body.TryGetProperty("dashboardUrl", out _));
    }

    [Fact]
    public async Task Text_LinksDashboardWhenSet()
    {
        var handler = new RecordingHandler();
        var store = Notifier(new InMemoryApprovalStore(), handler, Settings(dashboard: new Uri("https://dash.example.com/")));
        await store.EnsureRequestAsync(Caller(), Spec(), Ctx(), TestContext.Current.CancellationToken);

        var body = Body(handler);
        Assert.EndsWith("https://dash.example.com/", body.GetProperty("text").GetString(), StringComparison.Ordinal);
        Assert.Equal("https://dash.example.com/", body.GetProperty("dashboardUrl").GetString());
    }

    [Fact]
    public async Task DashboardUrl_KeepsPercentEscapes()
    {
        var handler = new RecordingHandler();
        var store = Notifier(new InMemoryApprovalStore(), handler, Settings(dashboard: new Uri("https://dash.example.com/my%20team/")));
        await store.EnsureRequestAsync(Caller(), Spec(), Ctx(), TestContext.Current.CancellationToken);

        var body = Body(handler);
        Assert.Equal("https://dash.example.com/my%20team/", body.GetProperty("dashboardUrl").GetString());
        Assert.EndsWith("https://dash.example.com/my%20team/", body.GetProperty("text").GetString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Text_LinksHttpApprovalUrlWhenNoDashboard()
    {
        var handler = new RecordingHandler();
        var http = new ApprovalState.Pending("r1", "https://portal.example.com/x", DateTimeOffset.UnixEpoch) { IsNew = true };
        await Notifier(new FixedStore(http), handler).EnsureRequestAsync(Caller(), Spec(), Ctx(), TestContext.Current.CancellationToken);
        Assert.EndsWith(" https://portal.example.com/x", Body(handler).GetProperty("text").GetString(), StringComparison.Ordinal);

        var other = new RecordingHandler();
        var custom = new ApprovalState.Pending("r2", "sentinel://approve/r2", DateTimeOffset.UnixEpoch) { IsNew = true };
        await Notifier(new FixedStore(custom), other).EnsureRequestAsync(Caller(), Spec(), Ctx(), TestContext.Current.CancellationToken);
        Assert.EndsWith("(approval:Bash).", Body(other).GetProperty("text").GetString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Text_PrefersDashboardOverHttpApprovalUrl()
    {
        var handler = new RecordingHandler();
        var inner = new FixedStore(new ApprovalState.Pending("r1", "https://portal.example.com/x", DateTimeOffset.UnixEpoch) { IsNew = true });
        var store = Notifier(inner, handler, Settings(dashboard: new Uri("https://dash.example.com/")));
        await store.EnsureRequestAsync(Caller(), Spec(), Ctx(), TestContext.Current.CancellationToken);

        var text = Body(handler).GetProperty("text").GetString()!;
        Assert.EndsWith("https://dash.example.com/", text, StringComparison.Ordinal);
        Assert.DoesNotContain("portal.example.com", text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Headers_Sent()
    {
        var handler = new RecordingHandler();
        var store = Notifier(new InMemoryApprovalStore(), handler, Settings(headers: ("Authorization", "Bearer t")));
        await store.EnsureRequestAsync(Caller(), Spec(), Ctx(), TestContext.Current.CancellationToken);

        Assert.Equal("Bearer t", handler.Calls.Single().Request.Headers.GetValues("Authorization").Single());
    }

    [Fact]
    public async Task IncludeArgs_RedactsSecretsAndPii()
    {
        const string key = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789ABCD";
        var args = "{\"cmd\":\"curl -H 'Authorization: Bearer " + key + "'\","
            + "\"nested\":{\"to\":\"alice@example.com\",\"deeper\":{\"note\":\"use api_key=" + key + " here\"}}}";
        var handler = new RecordingHandler();
        var store = Notifier(new InMemoryApprovalStore(), handler, Settings(includeArgs: true));
        await store.EnsureRequestAsync(Caller(), Spec(), Ctx(args), TestContext.Current.CancellationToken);

        var raw = handler.Calls.Single().Body;
        Assert.Contains("\"cmd\"", raw, StringComparison.Ordinal);
        Assert.Contains("\"to\"", raw, StringComparison.Ordinal);
        Assert.DoesNotContain(key, raw, StringComparison.Ordinal);
        Assert.DoesNotContain("abcdefghijklmnopqrstuvwxyz", raw, StringComparison.Ordinal);
        Assert.DoesNotContain("alice@example.com", raw, StringComparison.Ordinal);
        Assert.Contains("[EMAIL_", raw, StringComparison.Ordinal);
        Assert.True(Body(handler).TryGetProperty("args", out _));
    }

    [Fact]
    public async Task Failure_Status500_ReturnsInnerStateAndLogs()
    {
        var logger = new CapturingLogger();
        var handler = new RecordingHandler((_, _) => Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.InternalServerError)));
        var url = new Uri("https://hooks.example.com/services/abc?token=s3cret");
        var inner = new FixedStore(new ApprovalState.Pending("r1", "sentinel://approve/r1", DateTimeOffset.UnixEpoch) { IsNew = true });
        var store = Notifier(inner, handler, Settings(url, headers: ("Authorization", "Bearer hdr-secret")), logger);

        var state = await store.EnsureRequestAsync(Caller(), Spec(), Ctx(), TestContext.Current.CancellationToken);

        Assert.Equal(await inner.EnsureRequestAsync(Caller(), Spec(), Ctx(), TestContext.Current.CancellationToken), state);
        AssertOneCleanWarning(logger);
    }

    [Fact]
    public async Task Failure_Exception_ReturnsInnerStateAndLogs()
    {
        var logger = new CapturingLogger();
        var handler = new RecordingHandler((_, _) => throw new HttpRequestException("boom https://hooks.example.com/services/abc?token=s3cret"));
        var url = new Uri("https://hooks.example.com/services/abc?token=s3cret");
        var inner = new FixedStore(new ApprovalState.Pending("r1", "sentinel://approve/r1", DateTimeOffset.UnixEpoch) { IsNew = true });
        var store = Notifier(inner, handler, Settings(url, headers: ("Authorization", "Bearer hdr-secret")), logger);

        var state = await store.EnsureRequestAsync(Caller(), Spec(), Ctx(), TestContext.Current.CancellationToken);

        Assert.Equal(await inner.EnsureRequestAsync(Caller(), Spec(), Ctx(), TestContext.Current.CancellationToken), state);
        AssertOneCleanWarning(logger);
    }

    private static void AssertOneCleanWarning(CapturingLogger logger)
    {
        var entry = Assert.Single(logger.Entries);
        Assert.Equal(LogLevel.Warning, entry.Level);
        Assert.Contains("https://hooks.example.com", entry.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("/services", entry.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("abc", entry.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("token", entry.Message, StringComparison.Ordinal);
        Assert.Contains("r1", entry.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("s3cret", entry.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("hdr-secret", entry.Message, StringComparison.Ordinal);
    }

    // The one slow test of this class: it waits out the real 3 s POST timeout. The test project has no slow-test
    // trait to mark it with.
    [Fact(Timeout = 15000)]
    public async Task Failure_Timeout_ReturnsWithinBudget()
    {
        var logger = new CapturingLogger();
        var handler = new RecordingHandler(async (_, ct) =>
        {
            await Task.Delay(Timeout.Infinite, ct);
            return new HttpResponseMessage();
        });
        var inner = new FixedStore(new ApprovalState.Pending("r1", "sentinel://approve/r1", DateTimeOffset.UnixEpoch) { IsNew = true });
        var store = Notifier(inner, handler, logger: logger);

        var clock = Stopwatch.StartNew();
        var state = await store.EnsureRequestAsync(Caller(), Spec(), Ctx(), TestContext.Current.CancellationToken);

        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(5), $"took {clock.Elapsed}");
        Assert.Equal(await inner.EnsureRequestAsync(Caller(), Spec(), Ctx(), TestContext.Current.CancellationToken), state);
        var entry = Assert.Single(logger.Entries);
        Assert.Equal(LogLevel.Warning, entry.Level);
        Assert.Contains("https://hooks.example.com", entry.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("/services", entry.Message, StringComparison.Ordinal);
        Assert.Contains("timed out", entry.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CallerCancelled_PropagatesCancellation_NoWarning()
    {
        var logger = new CapturingLogger();
        using var cts = new CancellationTokenSource();
        var handler = new RecordingHandler(async (_, ct) =>
        {
            await cts.CancelAsync();
            await Task.Delay(Timeout.Infinite, ct);
            return new HttpResponseMessage();
        });
        var store = Notifier(new InMemoryApprovalStore(), handler, logger: logger);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await store.EnsureRequestAsync(Caller(), Spec(), Ctx(), cts.Token));
        Assert.Empty(logger.Entries);
    }

    [Fact]
    public void Wrap_PicksTheVariantByTheInnerStore()
    {
        var settings = Settings();
        var withAdmin = NotifyingApprovalStore.Wrap(new InMemoryApprovalStore(), settings, null);
        Assert.IsType<NotifyingApprovalAdminStore>(withAdmin);
        Assert.IsAssignableFrom<IApprovalAdmin>(withAdmin);

        var plain = NotifyingApprovalStore.Wrap(new FixedStore(new ApprovalState.Denied("x", DateTimeOffset.UnixEpoch)), settings, null);
        Assert.IsType<NotifyingApprovalStore>(plain);
        Assert.IsNotAssignableFrom<IApprovalAdmin>(plain);
    }

    [Fact]
    public async Task AdminVariant_ForwardsAdmin()
    {
        var inner = new InMemoryApprovalStore();
        var wrapped = new NotifyingApprovalAdminStore(inner, Settings(), new RecordingHandler(), null);
        var ct = TestContext.Current.CancellationToken;

        var first = (ApprovalState.Pending)await wrapped.EnsureRequestAsync(Caller(), Spec(), Ctx(), ct);
        var secondSpec = new ApprovalSpec { PolicyName = "approval:Other" };
        var second = (ApprovalState.Pending)await wrapped.EnsureRequestAsync(Caller(), secondSpec, Ctx(), ct);

        var listed = new List<string>();
        await foreach (var p in ((IApprovalAdmin)wrapped).ListPendingAsync(ct))
        {
            listed.Add(p.RequestId);
        }
        Assert.Equal(new[] { first.RequestId, second.RequestId }.Order(StringComparer.Ordinal), listed.Order(StringComparer.Ordinal));

        await ((IApprovalAdmin)wrapped).ApproveAsync(first.RequestId, "bob", null, ct);
        await ((IApprovalAdmin)wrapped).DenyAsync(second.RequestId, "bob", "no", ct);

        Assert.IsType<ApprovalState.Active>(await inner.WaitForDecisionAsync(first.RequestId, TimeSpan.Zero, ct));
        var denied = Assert.IsType<ApprovalState.Denied>(await inner.WaitForDecisionAsync(second.RequestId, TimeSpan.Zero, ct));
        Assert.Contains("no", denied.Reason, StringComparison.Ordinal);
        Assert.Same(inner, wrapped.Inner);
    }
}
