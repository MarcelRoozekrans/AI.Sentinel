using System.Runtime.CompilerServices;
using AI.Sentinel.Audit;
using AI.Sentinel.Authorization;
using AI.Sentinel.Authorization.Policies;
using AI.Sentinel.Tests.Helpers;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.DependencyInjection;
using Xunit;
using ZeroAlloc.Authorization;

namespace AI.Sentinel.Tests.Authorization.Integration;

/// <summary>
/// A tool the MODEL asks for is run by FunctionInvokingChatClient, so it never appears in the
/// messages the caller sends. These tests pin that authorization still runs before the tool.
/// </summary>
public class ModelInitiatedToolCallTests
{
    public static TheoryData<bool> Orders => new() { true, false };

    private sealed class Harness(int[] ran, IChatClient client, RingBufferAuditStore audit, ChatOptions options)
    {
        public int Ran => ran[0];
        public IChatClient Client => client;
        public RingBufferAuditStore Audit => audit;
        public ChatOptions Options => options;
    }

    // ChatClientBuilder: the FIRST Use is the OUTERMOST client.
    private static Harness Build(bool authorizationOutside, ISecurityContext caller, bool toolsViaAdditionalTools = false, bool modelCallsTool = true)
    {
        var opts = new SentinelOptions().RequireToolPolicy("DeleteUser", "admin-only");
        var audit = new RingBufferAuditStore();
        var services = new ServiceCollection();
        services.AddSingleton(opts);
        services.AddSingleton<IAuditStore>(audit);
        services.AddSingleton(caller);
        services.AddSingleton<IToolCallGuard>(_ => new DefaultToolCallGuard(
            opts.GetAuthorizationBindings(),
            new Dictionary<string, IAuthorizationPolicy>(StringComparer.Ordinal) { ["admin-only"] = new AdminOnlyPolicy() },
            opts.DefaultToolPolicy, approvalStore: null, logger: null));
        var sp = services.BuildServiceProvider();

        var ran = new int[1];
        var tool = AIFunctionFactory.Create((string id) => { ran[0]++; return "deleted " + id; }, "DeleteUser");

        var builder = new ChatClientBuilder(new ScriptedModel(modelCallsTool));
        Action<FunctionInvokingChatClient> configure = f =>
        {
            if (toolsViaAdditionalTools)
            {
                f.AdditionalTools = [tool];
            }
        };
        var client = (authorizationOutside
            ? builder.UseToolCallAuthorization().UseFunctionInvocation(null, configure)
            : builder.UseFunctionInvocation(null, configure).UseToolCallAuthorization()).Build(sp);
        return new Harness(ran, client, audit, toolsViaAdditionalTools ? new ChatOptions() : new ChatOptions { Tools = [tool] });
    }

    private static Task<ChatResponse> AskAsync(Harness h)
        => h.Client.GetResponseAsync([new ChatMessage(ChatRole.User, "delete 42")], h.Options, TestContext.Current.CancellationToken);

    private static async Task DrainAsync(Harness h)
    {
        await foreach (var _ in h.Client.GetStreamingResponseAsync(
            [new ChatMessage(ChatRole.User, "delete 42")], h.Options, TestContext.Current.CancellationToken))
        {
        }
    }

    [Fact]
    public async Task AuthorizationOutsideFunctionInvocation_DeniedCall_ToolNeverRunsAndDenialReachesCaller()
    {
        var h = Build(authorizationOutside: true, new TestSecurityContext("bob"));

        await Assert.ThrowsAsync<ToolCallAuthorizationException>(() => AskAsync(h));

        Assert.Equal(0, h.Ran);
    }

    [Fact]
    public async Task AuthorizationInsideFunctionInvocation_DeniedCall_ToolNeverRuns()
    {
        var h = Build(authorizationOutside: false, new TestSecurityContext("bob"));

        await Assert.ThrowsAsync<ToolCallAuthorizationException>(() => AskAsync(h));

        Assert.Equal(0, h.Ran);
    }

    [Theory]
    [MemberData(nameof(Orders))]
    public async Task DeniedModelCall_Streaming_ToolNeverRuns(bool authorizationOutside)
    {
        var h = Build(authorizationOutside, new TestSecurityContext("bob"));

        await Assert.ThrowsAsync<ToolCallAuthorizationException>(() => DrainAsync(h));

        Assert.Equal(0, h.Ran);
    }

    [Theory]
    [MemberData(nameof(Orders))]
    public async Task DeniedModelCall_WritesOneAuthzDenyEntry(bool authorizationOutside)
    {
        var h = Build(authorizationOutside, new TestSecurityContext("bob"));

        await Assert.ThrowsAsync<ToolCallAuthorizationException>(() => AskAsync(h));

        var entry = Assert.Single(await RecordingAuditForwarder.ReadAllAsync(h.Audit));
        Assert.Equal("AUTHZ-DENY", entry.DetectorId);
    }

    [Theory]
    [MemberData(nameof(Orders))]
    public async Task AllowedModelCall_ToolRunsOnce(bool authorizationOutside)
    {
        var h = Build(authorizationOutside, new TestSecurityContext("alice", "admin"));

        var response = await AskAsync(h);

        Assert.Equal(1, h.Ran);
        Assert.Equal("done", response.Text);
        Assert.Empty(await RecordingAuditForwarder.ReadAllAsync(h.Audit));
    }

    [Theory]
    [MemberData(nameof(Orders))]
    public async Task DeniedModelCall_ToolFromAdditionalTools_NeverRunsAndIsAuditedOnce(bool authorizationOutside)
    {
        var h = Build(authorizationOutside, new TestSecurityContext("bob"), toolsViaAdditionalTools: true);

        await Assert.ThrowsAsync<ToolCallAuthorizationException>(() => AskAsync(h));

        Assert.Equal(0, h.Ran);
        Assert.Equal("AUTHZ-DENY", Assert.Single(await RecordingAuditForwarder.ReadAllAsync(h.Audit)).DetectorId);
    }

    [Theory]
    [MemberData(nameof(Orders))]
    public async Task AllowedModelCall_ToolFromAdditionalTools_RunsOnce(bool authorizationOutside)
    {
        var h = Build(authorizationOutside, new TestSecurityContext("alice", "admin"), toolsViaAdditionalTools: true);

        await AskAsync(h);

        Assert.Equal(1, h.Ran);
    }

    // A denied call that a caller kept in history (call plus its failed result) is history on the next
    // turn: it must not throw again or be audited a second time.
    [Theory]
    [MemberData(nameof(Orders))]
    public async Task AnsweredCallInHistory_IsNotAuthorizedAgain(bool authorizationOutside)
    {
        var h = Build(authorizationOutside, new TestSecurityContext("bob"), modelCallsTool: false);
        var history = new List<ChatMessage>
        {
            new(ChatRole.User, "delete 42"),
            new(ChatRole.Assistant, [new FunctionCallContent("c1", "DeleteUser", new Dictionary<string, object?>(StringComparer.Ordinal) { ["id"] = "42" })]),
            new(ChatRole.Tool, [new FunctionResultContent("c1", "Error: Function failed.")]),
            new(ChatRole.User, "thanks"),
        };

        var response = await h.Client.GetResponseAsync(history, new ChatOptions(), TestContext.Current.CancellationToken);

        Assert.Equal(0, h.Ran);
        Assert.NotNull(response);
        Assert.Empty(await RecordingAuditForwarder.ReadAllAsync(h.Audit));
    }

    [Theory]
    [MemberData(nameof(Orders))]
    public async Task DeniedModelCall_Streaming_WritesOneAuthzDenyEntry(bool authorizationOutside)
    {
        var h = Build(authorizationOutside, new TestSecurityContext("bob"));

        await Assert.ThrowsAsync<ToolCallAuthorizationException>(() => DrainAsync(h));

        Assert.Equal("AUTHZ-DENY", Assert.Single(await RecordingAuditForwarder.ReadAllAsync(h.Audit)).DetectorId);
    }

    private static (AuthorizationChatClient Client, int[] Ran, ChatOptions Options, RingBufferAuditStore Audit) BuildDirect(
        Func<ISecurityContext> caller, IChatClient model)
    {
        var opts = new SentinelOptions().RequireToolPolicy("DeleteUser", "admin-only");
        var audit = new RingBufferAuditStore();
        var guard = new DefaultToolCallGuard(
            opts.GetAuthorizationBindings(),
            new Dictionary<string, IAuthorizationPolicy>(StringComparer.Ordinal) { ["admin-only"] = new AdminOnlyPolicy() },
            opts.DefaultToolPolicy, approvalStore: null, logger: null);
        var ran = new int[1];
        var tool = AIFunctionFactory.Create((string id) => { Interlocked.Increment(ref ran[0]); return "deleted " + id; }, "DeleteUser");
        var client = new AuthorizationChatClient(new FunctionInvokingChatClient(model), guard, caller, audit);
        return (client, ran, new ChatOptions { Tools = [tool] }, audit);
    }

    [Fact]
    public async Task ConcurrentRequestsWithTheSameCallId_EachGetsItsOwnOutcome()
    {
        var current = new AsyncLocal<ISecurityContext?>();
        var model = new GatedModel(parties: 2);
        var (client, ran, options, audit) = BuildDirect(() => current.Value ?? AnonymousSecurityContext.Instance, model);
        var ct = TestContext.Current.CancellationToken;

        Task<ToolCallAuthorizationException?> Run(ISecurityContext who) => Task.Run(async () =>
        {
            current.Value = who;
            try
            {
                await client.GetResponseAsync([new ChatMessage(ChatRole.User, "delete 42")], options, ct);
                return null;
            }
            catch (ToolCallAuthorizationException ex)
            {
                return ex;
            }
        }, ct);

        var bob = Run(new TestSecurityContext("bob"));
        var alice = Run(new TestSecurityContext("alice", "admin"));

        Assert.IsType<ToolCallAuthorizationException>(await bob);
        Assert.Null(await alice);
        Assert.Equal(1, ran[0]);
        Assert.Single(await RecordingAuditForwarder.ReadAllAsync(audit));
    }

    [Fact]
    public async Task StreamingOutside_LeavesNoStateBehind_LaterRequestWithTheSameCallIdIsEvaluatedFresh()
    {
        ISecurityContext caller = new TestSecurityContext("alice", "admin");
        var (client, ran, options, audit) = BuildDirect(() => caller, new ScriptedModel(callsTool: true));
        var ct = TestContext.Current.CancellationToken;

        await foreach (var _ in client.GetStreamingResponseAsync([new ChatMessage(ChatRole.User, "delete 42")], options, ct))
        {
        }

        Assert.Equal(1, ran[0]);

        caller = new TestSecurityContext("bob");
        await Assert.ThrowsAsync<ToolCallAuthorizationException>(() =>
            client.GetResponseAsync([new ChatMessage(ChatRole.User, "delete 42")], options, ct));
        Assert.Equal(1, ran[0]);
        Assert.Single(await RecordingAuditForwarder.ReadAllAsync(audit));
    }

    // Asks for DeleteUser c1 first; once `parties` requests have all reached their second call, answers "done".
    private sealed class GatedModel(int parties) : IChatClient
    {
        private readonly TaskCompletionSource _release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int _waiting;

        public async Task<ChatResponse> GetResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, CancellationToken cancellationToken = default)
        {
            var answered = false;
            foreach (var m in messages)
            {
                foreach (var c in m.Contents)
                {
                    answered |= c is FunctionResultContent;
                }
            }

            if (!answered)
            {
                return new ChatResponse(new ChatMessage(ChatRole.Assistant, [new FunctionCallContent("c1", "DeleteUser", new Dictionary<string, object?>(StringComparer.Ordinal) { ["id"] = "42" })]));
            }

            if (Interlocked.Increment(ref _waiting) == parties)
            {
                _release.SetResult();
            }

            await _release.Task.WaitAsync(cancellationToken);
            return new ChatResponse(new ChatMessage(ChatRole.Assistant, "done"));
        }

        public IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        public object? GetService(Type serviceType, object? serviceKey = null) => null;

        public void Dispose() { }
    }

    private sealed class ScriptedModel(bool callsTool) : IChatClient
    {
        // Asks for the tool until a function result is in the conversation, so each request asks again.
        public Task<ChatResponse> GetResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, CancellationToken cancellationToken = default)
        {
            var answered = false;
            foreach (var m in messages)
            {
                foreach (var c in m.Contents)
                {
                    answered |= c is FunctionResultContent;
                }
            }

            var reply = callsTool && !answered
                ? new ChatMessage(ChatRole.Assistant, [new FunctionCallContent("c1", "DeleteUser", new Dictionary<string, object?>(StringComparer.Ordinal) { ["id"] = "42" })])
                : new ChatMessage(ChatRole.Assistant, "done");
            return Task.FromResult(new ChatResponse(reply));
        }

        public async IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, [EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            var response = await GetResponseAsync(messages, options, cancellationToken).ConfigureAwait(false);
            foreach (var update in response.ToChatResponseUpdates())
            {
                yield return update;
            }
        }

        public object? GetService(Type serviceType, object? serviceKey = null) => null;

        public void Dispose() { }
    }
}
