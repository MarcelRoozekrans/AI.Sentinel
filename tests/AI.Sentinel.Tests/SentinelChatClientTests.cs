using Xunit;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.DependencyInjection;
using AI.Sentinel;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using AI.Sentinel.Audit;
using AI.Sentinel.Intervention;
using AI.Sentinel.Detectors.Operational;

public class SentinelChatClientTests
{
    private static IChatClient BuildSentinelClient(
        IChatClient inner, SentinelOptions? opts = null, IDetector[]? detectors = null)
    {
        var options = opts ?? new SentinelOptions();
        var pipeline = new DetectionPipeline(
            detectors ?? [new BlankResponseDetector()], null);
        var store = new RingBufferAuditStore();
        var engine = new InterventionEngine(options, mediator: null);
        return new SentinelChatClient(inner, pipeline, store, engine, options);
    }

    [Fact] public async Task CleanMessage_PassesThrough()
    {
        var inner = new FakeChatClient("Hello!");
        var client = BuildSentinelClient(inner);
        var result = await client.GetResponseAsync(
            new List<ChatMessage> { new(ChatRole.User, "hi") });
        Assert.Contains("Hello!", result.Text ?? "");
    }

    [Fact] public async Task CriticalThreat_WithQuarantine_ThrowsSentinelException()
    {
        var inner = new FakeChatClient("response");
        var client = BuildSentinelClient(inner,
            opts: new SentinelOptions { OnCritical = SentinelAction.Quarantine },
            detectors: [new FakeCriticalDetector()]);

        await Assert.ThrowsAsync<SentinelException>(
            () => client.GetResponseAsync(
                new List<ChatMessage> { new(ChatRole.User, "inject") }));
    }

    private sealed class FakeCriticalDetector : IDetector
    {
        public DetectorId Id => new("TST-99");
        public DetectorCategory Category => DetectorCategory.Security;
        public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct) =>
            ValueTask.FromResult(DetectionResult.WithSeverity(Id, Severity.Critical, "fake threat"));
    }

    private sealed class FakeChatClient(string responseText) : IChatClient
    {
        public void Dispose() { }
        public object? GetService(Type serviceType, object? key = null) => null;

        public Task<ChatResponse> GetResponseAsync(
            IEnumerable<ChatMessage> messages,
            ChatOptions? options = null,
            CancellationToken cancellationToken = default) =>
            Task.FromResult(new ChatResponse(new ChatMessage(ChatRole.Assistant, responseText)));

        public IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(
            IEnumerable<ChatMessage> messages,
            ChatOptions? options = null,
            CancellationToken cancellationToken = default) =>
            throw new NotImplementedException();
    }
}
