using AI.Sentinel.Tools;
using Microsoft.Extensions.AI;
using Xunit;

namespace AI.Sentinel.Tests.Tools;

public class ToolInvocationInterceptionTests
{
    private static async Task<(string Text, int Ran, string? SeenId, string? ResultSeenByModel)> RunAsync(
        Action<FunctionInvokingChatClient>? preset, Action<IChatClient>? chain)
    {
        var ran = 0;
        string? seen = null;
        var tool = AIFunctionFactory.Create((string id) => { ran++; seen = id; return "deleted " + id; }, "DeleteUser");
        var invoking = new FunctionInvokingChatClient(new CallOnceModel());
        preset?.Invoke(invoking);
        chain?.Invoke(invoking);
        var response = await invoking.GetResponseAsync(
            [new ChatMessage(ChatRole.User, "go")], new ChatOptions { Tools = [tool] }, TestContext.Current.CancellationToken);
        string? result = null;
        foreach (var msg in response.Messages)
        {
            foreach (var content in msg.Contents)
            {
                if (content is FunctionResultContent r)
                {
                    result = r.Result?.ToString();
                }
            }
        }

        return (response.Text, ran, seen, result);
    }

    [Fact]
    public void TryChainInvoker_NoFunctionInvokingClient_ReturnsFalse()
    {
        Assert.False(ToolInvocationInterception.TryChainInvoker(new CallOnceModel(), (c, next, ct) => next(c, ct)));
    }

    [Fact]
    public async Task TryChainInvoker_ChainsAnExistingInvoker_InsteadOfOverwritingIt()
    {
        var log = new List<string>();
        var (_, ran, _, _) = await RunAsync(
            f => f.FunctionInvoker = async (c, ct) =>
            {
                log.Add("existing");
                return await c.Function.InvokeAsync(c.Arguments, ct);
            },
            f => Assert.True(ToolInvocationInterception.TryChainInvoker(f, async (c, next, ct) =>
            {
                log.Add("hook");
                return await next(c, ct);
            })));

        Assert.Equal(["hook", "existing"], log);
        Assert.Equal(1, ran);
    }

    [Fact]
    public async Task TryChainInvoker_TwoInterceptors_BothRun_LaterChainedFirst()
    {
        var log = new List<string>();
        await RunAsync(null, f =>
        {
            ToolInvocationInterception.TryChainInvoker(f, async (c, next, ct) => { log.Add("first-in"); var r = await next(c, ct); log.Add("first-out"); return r; });
            ToolInvocationInterception.TryChainInvoker(f, async (c, next, ct) => { log.Add("second-in"); var r = await next(c, ct); log.Add("second-out"); return r; });
        });

        Assert.Equal(["second-in", "first-in", "first-out", "second-out"], log);
    }

    [Fact]
    public async Task Interceptor_CanReplaceArgumentsAndResult()
    {
        var (text, ran, seen, modelSaw) = await RunAsync(null, f =>
            ToolInvocationInterception.TryChainInvoker(f, async (c, next, ct) =>
            {
                c.Arguments = new AIFunctionArguments(new Dictionary<string, object?>(StringComparer.Ordinal) { ["id"] = "swapped" }, StringComparer.Ordinal);
                var result = await next(c, ct);
                return "wrapped:" + result;
            }));

        Assert.Equal(1, ran);
        Assert.Equal("swapped", seen, StringComparer.Ordinal);
        Assert.Equal("done", text, StringComparer.Ordinal);
        Assert.Equal("wrapped:deleted swapped", modelSaw, StringComparer.Ordinal);
    }

    [Fact]
    public async Task Interceptor_Throwing_StopsTheToolFromRunning()
    {
        var (_, ran, _, _) = await RunAsync(null, f =>
            ToolInvocationInterception.TryChainInvoker(f, (c, next, ct) => throw new InvalidOperationException("no")));

        Assert.Equal(0, ran);
    }

    private sealed class CallOnceModel : IChatClient
    {
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

            return Task.FromResult(new ChatResponse(answered
                ? new ChatMessage(ChatRole.Assistant, "done")
                : new ChatMessage(ChatRole.Assistant, [new FunctionCallContent("c1", "DeleteUser", new Dictionary<string, object?>(StringComparer.Ordinal) { ["id"] = "42" })])));
        }

        public IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        public object? GetService(Type serviceType, object? serviceKey = null) => null;

        public void Dispose() { }
    }
}
