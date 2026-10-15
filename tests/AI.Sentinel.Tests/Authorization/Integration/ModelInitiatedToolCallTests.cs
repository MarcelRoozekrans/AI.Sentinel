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
    public async Task StreamingOutside_LeavesNoStateBehind_LaterRequestForAnUndecidedCallIsEvaluatedFresh()
    {
        ISecurityContext caller = new TestSecurityContext("alice", "admin");
        var (client, ran, options, audit) = BuildDirect(() => caller, new ScriptedModel(callsTool: true));
        var ct = TestContext.Current.CancellationToken;

        await foreach (var _ in client.GetStreamingResponseAsync([new ChatMessage(ChatRole.User, "delete 42")], options, ct))
        {
        }

        Assert.Equal(1, ran[0]);

        // Same call id c1, but DeleteUser is not registered, so the invocation hook never decides it and
        // only the response check can. A stale "allowed" left by the stream would let it through.
        caller = new TestSecurityContext("bob");
        await Assert.ThrowsAsync<ToolCallAuthorizationException>(() =>
            client.GetResponseAsync([new ChatMessage(ChatRole.User, "delete 42")], new ChatOptions(), ct));
        Assert.Equal(1, ran[0]);
        Assert.Single(await RecordingAuditForwarder.ReadAllAsync(audit));
    }

    // Scripts a conversation by what has been answered so far. Prompt "outer": c1 Outer, then c2 DeleteUser.
    // Prompt "nested": c2 Safe. Prompt "turns": c1 DeleteUser, then c1 Safe.
    private sealed class PromptModel : IChatClient
    {
        public Task<ChatResponse> GetResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, CancellationToken cancellationToken = default)
        {
            var list = messages.ToList();
            var prompt = list[0].Text;
            var results = 0;
            foreach (var m in list)
            {
                foreach (var c in m.Contents)
                {
                    results += c is FunctionResultContent ? 1 : 0;
                }
            }

            (string Id, string Name)? call = (prompt, results) switch
            {
                ("outer", 0) => ("c1", "Outer"),
                ("outer", 1) => ("c2", "DeleteUser"),
                ("nested", 0) => ("c2", "Safe"),
                ("turns", 0) => ("c1", "DeleteUser"),
                ("turns", 1) => ("c1", "Safe"),
                _ => null,
            };
            var reply = call is { } c0
                ? new ChatMessage(ChatRole.Assistant, [new FunctionCallContent(c0.Id, c0.Name, new Dictionary<string, object?>(StringComparer.Ordinal) { ["id"] = "42" })])
                : new ChatMessage(ChatRole.Assistant, "done");
            return Task.FromResult(new ChatResponse(reply));
        }

        public IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, CancellationToken cancellationToken = default)
            => StreamAsync(messages, options, cancellationToken);

        private async IAsyncEnumerable<ChatResponseUpdate> StreamAsync(IEnumerable<ChatMessage> messages, ChatOptions? options, [EnumeratorCancellation] CancellationToken ct)
        {
            var response = await GetResponseAsync(messages, options, ct).ConfigureAwait(false);
            foreach (var update in response.ToChatResponseUpdates())
            {
                yield return update;
            }
        }

        public object? GetService(Type serviceType, object? serviceKey = null) => null;

        public void Dispose() { }
    }

    private static AuthorizationChatClient BuildPrompted(
        out IList<AITool> tools, out RingBufferAuditStore audit, Func<AuthorizationChatClient, IList<AITool>> makeTools, string caller = "bob")
    {
        var opts = new SentinelOptions().RequireToolPolicy("DeleteUser", "admin-only");
        audit = new RingBufferAuditStore();
        var guard = new DefaultToolCallGuard(
            opts.GetAuthorizationBindings(),
            new Dictionary<string, IAuthorizationPolicy>(StringComparer.Ordinal) { ["admin-only"] = new AdminOnlyPolicy() },
            opts.DefaultToolPolicy, approvalStore: null, logger: null);
        var client = new AuthorizationChatClient(new FunctionInvokingChatClient(new PromptModel()), guard, () => new TestSecurityContext(caller), audit);
        tools = makeTools(client);
        return client;
    }

    // A streaming call made from inside a tool must not write into the enclosing request's outcomes. If it
    // did, its allowed c2 would hide the outer request's later c2, which the hook never decides because
    // DeleteUser is not registered.
    [Fact]
    public async Task NestedStreamingCallInsideATool_DoesNotLeakIntoTheEnclosingRequest()
    {
        var ct = TestContext.Current.CancellationToken;
        AuthorizationChatClient? self = null;
        var client = BuildPrompted(out var tools, out _, _ =>
        [
            AIFunctionFactory.Create(async () =>
            {
                await foreach (var _ in self!.GetStreamingResponseAsync([new ChatMessage(ChatRole.User, "nested")], new ChatOptions { Tools = [AIFunctionFactory.Create(() => "ok", "Safe")] }, ct))
                {
                }

                return "outer-done";
            }, "Outer"),
        ]);
        self = client;

        await Assert.ThrowsAsync<ToolCallAuthorizationException>(() =>
            client.GetResponseAsync([new ChatMessage(ChatRole.User, "outer")], new ChatOptions { Tools = tools }, ct));
    }

    [Fact]
    public async Task DenialInAnEarlierTurn_IsNotOverwrittenByALaterAllowedCallWithTheSameId()
    {
        var ct = TestContext.Current.CancellationToken;
        var ran = 0;
        var client = BuildPrompted(out var tools, out var audit, _ =>
        [
            AIFunctionFactory.Create(() => { ran++; return "x"; }, "DeleteUser"),
            AIFunctionFactory.Create(() => "ok", "Safe"),
        ]);

        await Assert.ThrowsAsync<ToolCallAuthorizationException>(() =>
            client.GetResponseAsync([new ChatMessage(ChatRole.User, "turns")], new ChatOptions { Tools = tools }, ct));

        Assert.Equal(0, ran);
        Assert.Single(await RecordingAuditForwarder.ReadAllAsync(audit));
    }

    [Fact]
    public async Task TwoClientsWithTheSameConfigurationOverOneFunctionInvokingClient_EvaluateACallOnce()
    {
        var ct = TestContext.Current.CancellationToken;
        var opts = new SentinelOptions().RequireToolPolicy("DeleteUser", "admin-only");
        var audit = new RingBufferAuditStore();
        var counting = new CountingGuard(new DefaultToolCallGuard(
            opts.GetAuthorizationBindings(),
            new Dictionary<string, IAuthorizationPolicy>(StringComparer.Ordinal) { ["admin-only"] = new AdminOnlyPolicy() },
            opts.DefaultToolPolicy, approvalStore: null, logger: null));
        var shared = new FunctionInvokingChatClient(new PromptModel());
        ISecurityContext Caller() => new TestSecurityContext("alice", "admin");
        _ = new AuthorizationChatClient(shared, counting, Caller, audit);   // e.g. an earlier Build()
        var second = new AuthorizationChatClient(shared, counting, Caller, audit);
        var ran = 0;
        var tool = AIFunctionFactory.Create(() => { ran++; return "x"; }, "Safe");

        await second.GetResponseAsync([new ChatMessage(ChatRole.User, "nested")], new ChatOptions { Tools = [tool] }, ct);

        Assert.Equal(1, ran);
        Assert.Equal(1, counting.Calls);
    }

    private sealed class CountingGuard(IToolCallGuard inner) : IToolCallGuard
    {
        public int Calls;

        public ValueTask<AuthorizationDecision> AuthorizeAsync(ISecurityContext caller, string toolName, System.Text.Json.JsonElement args, CancellationToken ct = default)
        {
            Interlocked.Increment(ref Calls);
            return inner.AuthorizeAsync(caller, toolName, args, ct);
        }
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
