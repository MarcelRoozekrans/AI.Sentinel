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
    private sealed record Call(string Session, IReadOnlyList<AuditEntry> History, bool HadLookup, int EarlierHits);

    private sealed class CapturingDetector : IDetector
    {
        public List<Call> Calls { get; } = [];
        public DetectorId Id { get; } = new("TEST-CAPTURE");
        public DetectorCategory Category => DetectorCategory.Operational;

        public async ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
        {
            var hits = ctx.EarlierHits is { } lookup ? await lookup(Id, ct) : -1;
            lock (Calls)
            {
                Calls.Add(new Call(ctx.SessionId.Value, ctx.History, ctx.EarlierHits is not null, hits));
            }
            return DetectionResult.WithSeverity(Id, Severity.Low, "always");
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

    // Entries are stamped with the real clock, so two appends can tie; this store makes each strictly later.
    private sealed class StrictlyIncreasingStore(IAuditStore inner) : IAuditStore
    {
        private long _ticks;

        public ValueTask<AuditEntry> AppendAsync(AuditEntry entry, CancellationToken ct) =>
            inner.AppendAsync(entry with { Timestamp = entry.Timestamp.AddTicks(Interlocked.Increment(ref _ticks)) }, ct);

        public IAsyncEnumerable<AuditEntry> QueryAsync(AuditQuery query, CancellationToken ct) => inner.QueryAsync(query, ct);
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
        IAuditStore store = throwOnQuery ? new ThrowingQueryStore(audit) : new StrictlyIncreasingStore(audit);
        var pipeline = new SentinelPipeline(new EchoClient(), new DetectionPipeline([detector], null, null),
            store, new InterventionEngine(opts, null), opts);
        return (pipeline, detector, audit, failures);
    }

    private static ChatOptions WithKey(string value) =>
        new() { AdditionalProperties = new AdditionalPropertiesDictionary { ["sentinel.session_id"] = value } };

    private static Task AskAsync(SentinelPipeline p, string session) =>
        p.GetResponseResultAsync([new ChatMessage(ChatRole.User, "Hello there")], WithKey(session), TestContext.Current.CancellationToken).AsTask();

    // The scans of one call, in order: the prompt scan first, then the response scan. Looked up by what each
    // scan can see, not by position in the capture list.
    private static Call[] Scans(CapturingDetector d, string session) =>
        d.Calls.Where(c => string.Equals(c.Session, session, StringComparison.Ordinal)).OrderBy(c => c.History.Count).ToArray();

    [Fact]
    public async Task History_HoldsEarlierEntriesOfTheSession_OldestFirst()
    {
        var (p, d, _, _) = Build();
        await AskAsync(p, "a");
        await AskAsync(p, "a");

        // Four scans, each seeing one entry more than the one before: 0, 1, 2, 3.
        var scans = Scans(d, "a");
        Assert.Equal([0, 1, 2, 3], scans.Select(c => c.History.Count));
        var last = scans[3].History;
        Assert.True(last[0].Timestamp < last[1].Timestamp);
        Assert.True(last[1].Timestamp < last[2].Timestamp);
        Assert.All(last, e => Assert.Equal("a", e.SessionId));
    }

    [Fact]
    public async Task History_ExcludesOtherSessions()
    {
        var (p, d, _, _) = Build();
        await AskAsync(p, "a");
        await AskAsync(p, "b");
        await AskAsync(p, "a");

        var scans = Scans(d, "a");
        Assert.Equal([0, 1, 2, 3], scans.Select(c => c.History.Count));
        Assert.All(scans.SelectMany(c => c.History), e => Assert.Equal("a", e.SessionId));
    }

    [Fact]
    public async Task History_ResponseLegSeesPromptLegEntries()
    {
        var (p, d, _, _) = Build();
        await AskAsync(p, "a");

        var scans = Scans(d, "a");
        Assert.Equal(2, scans.Length);
        Assert.Empty(scans[0].History);
        Assert.Single(scans[1].History);
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
    public async Task EarlierHits_CountsTheDetectorsEarlierHitsInTheSameSessionOnly()
    {
        var (p, d, _, _) = Build();
        await AskAsync(p, "a");
        await AskAsync(p, "b");
        await AskAsync(p, "a");

        Assert.All(d.Calls, c => Assert.True(c.HadLookup));
        var a = Scans(d, "a");
        Assert.Equal(0, a[0].EarlierHits);
        Assert.True(a[3].EarlierHits > 0);
        var b = Scans(d, "b");
        Assert.Equal(0, b[0].EarlierHits);
    }

    [Fact]
    public async Task CancellationDuringTheHistoryRead_PropagatesAndIsNotReportedAsAFailure()
    {
        var failures = new List<string>();
        var opts = new SentinelOptions { OnDetectorFailure = failures.Add };
        using var cts = new CancellationTokenSource();
        var store = new CancellingQueryStore(cts);
        var p = new SentinelPipeline(new EchoClient(), new DetectionPipeline([new CapturingDetector()], null, null),
            store, new InterventionEngine(opts, null), opts);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            p.GetResponseResultAsync([new ChatMessage(ChatRole.User, "Hello there")], WithKey("a"), cts.Token).AsTask());
        Assert.True(store.Queried);
        Assert.Empty(failures);
    }

    private sealed class CancellingQueryStore(CancellationTokenSource cts) : IAuditStore
    {
        public bool Queried { get; private set; }

        public ValueTask<AuditEntry> AppendAsync(AuditEntry entry, CancellationToken ct) => ValueTask.FromResult(entry);

        public IAsyncEnumerable<AuditEntry> QueryAsync(AuditQuery query, CancellationToken ct)
        {
            Queried = true;
            cts.Cancel();
            throw new OperationCanceledException(ct);
        }
    }
}
