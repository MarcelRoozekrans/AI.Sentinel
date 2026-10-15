using System.Runtime.CompilerServices;
using AI.Sentinel.Audit;
using AI.Sentinel.Authorization;
using AI.Sentinel.Authorization.Policies;
using AI.Sentinel.Tests.Helpers;
using AI.Sentinel.Tools;
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
    private static Harness Build(bool authorizationOutside, ISecurityContext caller)
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

        var builder = new ChatClientBuilder(new ScriptedModel());
        var client = (authorizationOutside
            ? builder.UseToolCallAuthorization().UseFunctionInvocation()
            : builder.UseFunctionInvocation().UseToolCallAuthorization()).Build(sp);
        return new Harness(ran, client, audit, new ChatOptions { Tools = [tool] });
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

    // FunctionInvokingChatClient catches an exception thrown by a function and reports it to the model
    // as a failed function result, so a denial does not reach the caller when authorization wraps it.
    [Fact]
    public async Task AuthorizationOutsideFunctionInvocation_DeniedCall_ToolNeverRunsAndModelGetsFailedResult()
    {
        var h = Build(authorizationOutside: true, new TestSecurityContext("bob"));

        var response = await AskAsync(h);

        Assert.Equal(0, h.Ran);
        FunctionResultContent? failed = null;
        foreach (var msg in response.Messages)
        {
            foreach (var content in msg.Contents)
            {
                if (content is FunctionResultContent r)
                {
                    failed = r;
                }
            }
        }
        Assert.NotNull(failed);
        Assert.IsType<ToolCallAuthorizationException>(failed.Exception);
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

        // Outside FunctionInvokingChatClient the denial is reported to the model instead of thrown.
        try
        {
            await AskAsync(h);
        }
        catch (ToolCallAuthorizationException) when (!authorizationOutside)
        {
        }

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

    [Fact]
    public async Task WrapTools_ReturnsClone_WrapsFunctionsOnce_AndLeavesOtherToolsAlone()
    {
        var fn = AIFunctionFactory.Create(() => "x", "Fn");
        var hosted = new HostedWebSearchTool();
        var original = new ChatOptions { Tools = [fn, hosted] };
        var calls = 0;
        ValueTask<object?> Interceptor(AIFunction inner, AIFunctionArguments args, CancellationToken ct)
        {
            calls++;
            return inner.InvokeAsync(args, ct);
        }

        var once = ToolInvocationInterception.WrapTools(original, Interceptor);
        var twice = ToolInvocationInterception.WrapTools(once, Interceptor);

        Assert.NotSame(original, once);
        Assert.Same(fn, original.Tools![0]);
        Assert.NotSame(fn, once!.Tools![0]);
        Assert.Same(hosted, once.Tools[1]);
        Assert.Same(once.Tools[0], twice!.Tools![0]);
        var result = await ((AIFunction)once.Tools[0]).InvokeAsync(new AIFunctionArguments(StringComparer.Ordinal), TestContext.Current.CancellationToken);
        Assert.Equal("x", result?.ToString(), StringComparer.Ordinal);
        Assert.Equal(1, calls);
    }

    [Fact]
    public void WrapTools_NoTools_ReturnsOptionsUnchanged()
    {
        var options = new ChatOptions();
        Assert.Same(options, ToolInvocationInterception.WrapTools(options, (inner, args, ct) => inner.InvokeAsync(args, ct)));
        Assert.Null(ToolInvocationInterception.WrapTools(null, (inner, args, ct) => inner.InvokeAsync(args, ct)));
    }

    private sealed class ScriptedModel : IChatClient
    {
        private int _calls;

        public Task<ChatResponse> GetResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, CancellationToken cancellationToken = default)
        {
            var reply = Interlocked.Increment(ref _calls) == 1
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
