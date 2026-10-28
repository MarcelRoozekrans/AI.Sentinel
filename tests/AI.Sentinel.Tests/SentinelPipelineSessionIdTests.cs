using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using AI.Sentinel.Intervention;
using Microsoft.Extensions.AI;
using Xunit;

namespace AI.Sentinel.Tests;

// In-process audit entries of one conversation share a session id, so the dashboard and alert
// de-duplication can group them.
public class SentinelPipelineSessionIdTests
{
    private sealed class LowDetector : IDetector
    {
        public DetectorId Id { get; } = new("TEST-LOW");
        public DetectorCategory Category => DetectorCategory.Operational;

        public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct) =>
            ValueTask.FromResult(DetectionResult.WithSeverity(Id, Severity.Low, "always"));
    }

    private sealed class EchoClient : IChatClient
    {
        public Task<ChatResponse> GetResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, CancellationToken cancellationToken = default)
            => Task.FromResult(new ChatResponse(new ChatMessage(ChatRole.Assistant, "a reply long enough")));

        public async IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            await Task.Yield();
            yield return new ChatResponseUpdate(ChatRole.Assistant, "a reply long enough");
        }

        public object? GetService(Type serviceType, object? serviceKey = null) => null;

        public void Dispose() { }
    }

    private static (SentinelPipeline Pipeline, RingBufferAuditStore Audit) Build()
    {
        var opts = new SentinelOptions();
        var audit = new RingBufferAuditStore(100);
        var pipeline = new SentinelPipeline(new EchoClient(), new DetectionPipeline([new LowDetector()], null, null),
            audit, new InterventionEngine(opts, null), opts);
        return (pipeline, audit);
    }

    private static ChatOptions WithKey(string value) =>
        new() { AdditionalProperties = new AdditionalPropertiesDictionary { ["sentinel.session_id"] = value } };

    private static async Task<HashSet<string?>> SessionIdsAsync(RingBufferAuditStore audit)
    {
        var ids = new HashSet<string?>(StringComparer.Ordinal);
        await foreach (var e in audit.QueryAsync(new AuditQuery(), TestContext.Current.CancellationToken))
        {
            ids.Add(e.SessionId);
        }
        return ids;
    }

    private static Task AskAsync(SentinelPipeline p, ChatOptions? options) =>
        p.GetResponseResultAsync([new ChatMessage(ChatRole.User, "Hello there")], options, TestContext.Current.CancellationToken).AsTask();

    [Fact]
    public async Task ExplicitKey_IsUsedForEveryEntry_AcrossCalls()
    {
        var (p, audit) = Build();
        await AskAsync(p, WithKey("conv-42"));
        await AskAsync(p, WithKey("conv-42"));

        Assert.Equal(["conv-42"], await SessionIdsAsync(audit));
    }

    [Fact]
    public async Task ConversationId_IsUsedWhenNoKey()
    {
        var (p, audit) = Build();
        await AskAsync(p, new ChatOptions { ConversationId = "resp_abc" });
        await AskAsync(p, new ChatOptions { ConversationId = "resp_abc" });

        Assert.Equal(["resp_abc"], await SessionIdsAsync(audit));
    }

    [Fact]
    public async Task ExplicitKey_WinsOverConversationId()
    {
        var (p, audit) = Build();
        var options = WithKey("conv-42");
        options.ConversationId = "resp_abc";
        await AskAsync(p, options);

        Assert.Equal(["conv-42"], await SessionIdsAsync(audit));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("   ")]
    public async Task NoUsableId_EachCallGetsItsOwn(string? key)
    {
        var (p, audit) = Build();
        var options = key is null ? null : WithKey(key);
        await AskAsync(p, options);
        await AskAsync(p, options);

        var ids = await SessionIdsAsync(audit);
        Assert.Equal(2, ids.Count);
        Assert.DoesNotContain(ids, string.IsNullOrWhiteSpace);
    }

    [Fact]
    public async Task NonStringKey_IsIgnored()
    {
        var (p, audit) = Build();
        var options = new ChatOptions
        {
            ConversationId = "resp_abc",
            AdditionalProperties = new AdditionalPropertiesDictionary { ["sentinel.session_id"] = 42 },
        };
        await AskAsync(p, options);

        Assert.Equal(["resp_abc"], await SessionIdsAsync(audit));
    }

    [Fact]
    public async Task SessionIdKey_AcceptsTypedSessionId()
    {
        var (p, audit) = Build();
        var options = new ChatOptions
        {
            AdditionalProperties = new AdditionalPropertiesDictionary { [SentinelPipeline.SessionIdKey] = new SessionId("typed-1") },
        };
        await AskAsync(p, options);

        Assert.Equal(["typed-1"], await SessionIdsAsync(audit));
    }

    [Fact]
    public async Task Streaming_UsesTheSameId()
    {
        var (p, audit) = Build();
        _ = await p.GetStreamingResultAsync([new ChatMessage(ChatRole.User, "Hello there")], WithKey("conv-42"), TestContext.Current.CancellationToken);

        Assert.Equal(["conv-42"], await SessionIdsAsync(audit));
    }

    [Fact]
    public async Task ScanMessages_WithoutExplicitSessionId_UsesTheOptions()
    {
        var (p, audit) = Build();
        _ = await p.ScanMessagesAsync([new ChatMessage(ChatRole.User, "Hello there")], new ChatOptions { ConversationId = "resp_abc" }, ct: TestContext.Current.CancellationToken);

        Assert.Equal(["resp_abc"], await SessionIdsAsync(audit));
    }

    [Fact]
    public async Task ScanMessages_ExplicitSessionId_WinsOverTheOptions()
    {
        var (p, audit) = Build();
        _ = await p.ScanMessagesAsync([new ChatMessage(ChatRole.User, "Hello there")], WithKey("conv-42"), new SessionId("hook-session"), TestContext.Current.CancellationToken);

        Assert.Equal(["hook-session"], await SessionIdsAsync(audit));
    }
}
