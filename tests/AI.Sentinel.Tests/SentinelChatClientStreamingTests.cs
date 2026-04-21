using System.Runtime.CompilerServices;
using Xunit;
using Microsoft.Extensions.AI;
using AI.Sentinel;
using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using AI.Sentinel.Intervention;

namespace AI.Sentinel.Tests;

public class SentinelChatClientStreamingTests
{
    private static IChatClient BuildClient(
        IChatClient inner,
        SentinelOptions? opts = null,
        IDetector[]? detectors = null)
    {
        var options = opts ?? new SentinelOptions();
        var pipeline = new DetectionPipeline(detectors ?? [], null);
        var store = new RingBufferAuditStore();
        var engine = new InterventionEngine(options, mediator: null);
        return new SentinelChatClient(inner, pipeline, store, engine, options);
    }

    [Fact]
    public async Task CleanInput_YieldsAllUpdates()
    {
        var inner = new StreamingFakeClient("hello", " world");
        var client = BuildClient(inner);

        var chunks = new List<ChatResponseUpdate>();
        await foreach (var update in client.GetStreamingResponseAsync(
            [new ChatMessage(ChatRole.User, "hi")]))
            chunks.Add(update);

        Assert.Equal(2, chunks.Count);
        Assert.Equal("hello world", string.Concat(chunks.Select(c => c.Text ?? "")));
    }

    [Fact]
    public async Task ThreatInPrompt_ThrowsSentinelException()
    {
        var inner = new StreamingFakeClient("response");
        var client = BuildClient(inner,
            opts: new SentinelOptions { OnCritical = SentinelAction.Quarantine },
            detectors: [new AlwaysCriticalDetector()]);

        await Assert.ThrowsAsync<SentinelException>(async () =>
        {
            await foreach (var _ in client.GetStreamingResponseAsync(
                [new ChatMessage(ChatRole.User, "hostile")]))
            { }
        });
    }

    [Fact]
    public async Task ThreatInResponse_ThrowsSentinelException()
    {
        var inner = new StreamingFakeClient("malicious reply");
        var client = BuildClient(inner,
            opts: new SentinelOptions { OnCritical = SentinelAction.Quarantine },
            detectors: [new ResponseOnlyDetector()]);

        await Assert.ThrowsAsync<SentinelException>(async () =>
        {
            await foreach (var _ in client.GetStreamingResponseAsync(
                [new ChatMessage(ChatRole.User, "clean prompt")]))
            { }
        });
    }

    [Fact]
    public async Task AuditEntry_WrittenForStreamingCall()
    {
        var store = new RingBufferAuditStore(100);
        var opts = new SentinelOptions { OnCritical = SentinelAction.Alert };
        var pipeline = new DetectionPipeline([new AlwaysCriticalDetector()], null);
        var engine = new InterventionEngine(opts, null);
        var client = new SentinelChatClient(
            new StreamingFakeClient("ok"), pipeline, store, engine, opts);

        await foreach (var _ in client.GetStreamingResponseAsync(
            [new ChatMessage(ChatRole.User, "hi")]))
        { }

        var entries = new List<AuditEntry>();
        await foreach (var entry in store.QueryAsync(new AuditQuery(), default))
            entries.Add(entry);
        Assert.NotEmpty(entries);
    }

    // ---- Detectors ----

    private sealed class AlwaysCriticalDetector : IDetector
    {
        public DetectorId Id => new("TST-99");
        public DetectorCategory Category => DetectorCategory.Security;
        public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct) =>
            ValueTask.FromResult(DetectionResult.WithSeverity(Id, Severity.Critical, "fake threat"));
    }

    private sealed class ResponseOnlyDetector : IDetector
    {
        public DetectorId Id => new("RESP-01");
        public DetectorCategory Category => DetectorCategory.Security;
        public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
        {
            var hasAssistantMessage = ctx.Messages.Any(m => m.Role == ChatRole.Assistant);
            return hasAssistantMessage
                ? ValueTask.FromResult(DetectionResult.WithSeverity(Id, Severity.Critical, "response threat"))
                : ValueTask.FromResult(DetectionResult.Clean(Id));
        }
    }

    // ---- Test double ----

    private sealed class StreamingFakeClient(params string[] chunks) : IChatClient
    {
        public Task<ChatResponse> GetResponseAsync(IEnumerable<ChatMessage> messages,
            ChatOptions? options = null, CancellationToken cancellationToken = default)
            => Task.FromResult(new ChatResponse(
                [new ChatMessage(ChatRole.Assistant, string.Concat(chunks))]));

        public async IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(
            IEnumerable<ChatMessage> messages,
            ChatOptions? options = null,
            [EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            foreach (var chunk in chunks)
            {
                await Task.Yield();
                yield return new ChatResponseUpdate(ChatRole.Assistant, chunk);
            }
        }

        public ChatClientMetadata Metadata => new("test", null, null);
        public object? GetService(Type serviceType, object? key = null) => null;
        public void Dispose() { }
    }
}
