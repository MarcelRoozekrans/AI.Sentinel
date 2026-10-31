using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using AI.Sentinel.Intervention;
using Microsoft.Extensions.AI;
using Xunit;

namespace AI.Sentinel.Tests;

// The pipeline hands each detector the session's recent audit entries and a lookup of earlier hits.
public class SentinelPipelineHistoryTests
{
    private sealed class CapturingDetector : IDetector
    {
        public List<IReadOnlyList<AuditEntry>> Histories { get; } = [];
        public List<bool> HadLookup { get; } = [];
        public DetectorId Id { get; } = new("TEST-CAPTURE");
        public DetectorCategory Category => DetectorCategory.Operational;

        public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
        {
            lock (Histories)
            {
                Histories.Add(ctx.History);
                HadLookup.Add(ctx.EarlierHits is not null);
            }
            return ValueTask.FromResult(DetectionResult.WithSeverity(Id, Severity.Low, "always"));
        }
    }

    private sealed class EchoClient : IChatClient
    {
        public Task<ChatResponse> GetResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, CancellationToken cancellationToken = default)
            => Task.FromResult(new ChatResponse(new ChatMessage(ChatRole.Assistant, "a reply long enough")));

        public IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        public object? GetService(Type serviceType, object? serviceKey = null) => null;

        public void Dispose() { }
    }

    private sealed class ThrowingQueryStore(IAuditStore inner) : IAuditStore
    {
        public ValueTask<AuditEntry> AppendAsync(AuditEntry entry, CancellationToken ct) => inner.AppendAsync(entry, ct);

        public IAsyncEnumerable<AuditEntry> QueryAsync(AuditQuery query, CancellationToken ct) =>
            throw new InvalidOperationException("query down");
    }

    private static (SentinelPipeline Pipeline, CapturingDetector Detector, RingBufferAuditStore Audit, List<string> Failures) Build(bool throwOnQuery = false)
    {
        var failures = new List<string>();
        var opts = new SentinelOptions { OnDetectorFailure = failures.Add };
        var audit = new RingBufferAuditStore(100);
        var detector = new CapturingDetector();
        IAuditStore store = throwOnQuery ? new ThrowingQueryStore(audit) : audit;
        var pipeline = new SentinelPipeline(new EchoClient(), new DetectionPipeline([detector], null, null),
            store, new InterventionEngine(opts, null), opts);
        return (pipeline, detector, audit, failures);
    }

    private static ChatOptions WithKey(string value) =>
        new() { AdditionalProperties = new AdditionalPropertiesDictionary { ["sentinel.session_id"] = value } };

    private static Task AskAsync(SentinelPipeline p, string session) =>
        p.GetResponseResultAsync([new ChatMessage(ChatRole.User, "Hello there")], WithKey(session), TestContext.Current.CancellationToken).AsTask();

    [Fact]
    public async Task History_HoldsEarlierEntriesOfTheSession_OldestFirst()
    {
        var (p, d, _, _) = Build();
        await AskAsync(p, "a");
        await AskAsync(p, "a");

        // Calls: prompt1, response1, prompt2, response2.
        Assert.Empty(d.Histories[0]);
        var prompt2 = d.Histories[2];
        Assert.Equal(2, prompt2.Count);
        Assert.True(prompt2[0].Timestamp <= prompt2[1].Timestamp);
        Assert.All(prompt2, e => Assert.Equal("a", e.SessionId));
    }

    [Fact]
    public async Task History_ExcludesOtherSessions()
    {
        var (p, d, _, _) = Build();
        await AskAsync(p, "a");
        await AskAsync(p, "b");
        await AskAsync(p, "a");

        var lastPrompt = d.Histories[4];
        Assert.Equal(2, lastPrompt.Count);
        Assert.All(lastPrompt, e => Assert.Equal("a", e.SessionId));
    }

    [Fact]
    public async Task History_ResponseLegSeesPromptLegEntries()
    {
        var (p, d, _, _) = Build();
        await AskAsync(p, "a");

        Assert.Empty(d.Histories[0]);
        Assert.Single(d.Histories[1]);
    }

    [Fact]
    public async Task History_StoreThrowsOnQuery_ScanStillReportsFindings()
    {
        var (p, _, audit, failures) = Build(throwOnQuery: true);

        var ex = await Record.ExceptionAsync(() => AskAsync(p, "a"));

        Assert.Null(ex);
        var entries = new List<AuditEntry>();
        await foreach (var e in audit.QueryAsync(new AuditQuery(), TestContext.Current.CancellationToken)) entries.Add(e);
        Assert.NotEmpty(entries);
        Assert.Contains(failures, m => m.Contains("audit history", StringComparison.Ordinal));
    }

    [Fact]
    public async Task EarlierHits_IsSetOnPipelineContexts()
    {
        var (p, d, _, _) = Build();
        await AskAsync(p, "a");

        Assert.NotEmpty(d.HadLookup);
        Assert.All(d.HadLookup, Assert.True);
    }
}
