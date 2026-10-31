using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using AI.Sentinel.Detectors.Security;
using AI.Sentinel.Domain;
using AI.Sentinel.Intervention;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AI.Sentinel.Tests.Detection;

// #439. New content over SentinelOptions.MaxScanBytes is cut for the detectors, and the pipeline adds one Critical
// SEC-00 finding: text Sentinel could not scan is a finding, not a pass.
public class ScanBudgetPipelineTests
{
    private const string Sec00 = "SEC-00";

    private sealed class ReplyClient(string reply) : IChatClient
    {
        public Task<ChatResponse> GetResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, CancellationToken cancellationToken = default)
            => Task.FromResult(new ChatResponse(new ChatMessage(ChatRole.Assistant, reply)));

        public async IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null,
            [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            await Task.Yield();
            yield return new ChatResponseUpdate(ChatRole.Assistant, reply);
        }

        public object? GetService(Type serviceType, object? serviceKey = null) => null;

        public void Dispose() { }
    }

    private sealed class FiringDetector : IDetector
    {
        public DetectorId Id { get; } = new("TEST-FIRE");
        public DetectorCategory Category => DetectorCategory.Operational;

        public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
            => ValueTask.FromResult(DetectionResult.WithSeverity(Id, Severity.High, "fires"));
    }

    private static (SentinelPipeline Pipeline, RingBufferAuditStore Audit) Build(
        SentinelOptions opts, IDetector[]? detectors = null, string reply = "fine",
        IReadOnlyDictionary<Type, DetectorConfiguration>? configurations = null)
    {
        var audit = new RingBufferAuditStore(100);
        var detection = new DetectionPipeline(detectors ?? [], configurations, reviewer: null, redactByDefault: opts.RedactByDefault);
        var pipeline = new SentinelPipeline(new ReplyClient(reply), detection, audit, new InterventionEngine(opts, null), opts);
        return (pipeline, audit);
    }

    private static bool Is(DetectionResult d, string id) => string.Equals(d.DetectorId.Value, id, StringComparison.Ordinal);

    private static ChatMessage[] User(int bytes) => [new(ChatRole.User, new string('a', bytes))];

    private static IReadOnlyList<DetectionResult> Detections(ZeroAlloc.Results.Result<ChatResponse, SentinelError> result)
        => Assert.IsType<SentinelError.ThreatDetected>(result.Error).Detections;

    private static async Task<List<AuditEntry>> Entries(RingBufferAuditStore audit)
    {
        var entries = new List<AuditEntry>();
        await foreach (var e in audit.QueryAsync(new AuditQuery(), CancellationToken.None))
            entries.Add(e);
        return entries;
    }

    [Fact]
    public async Task Oversize_AddsCriticalSec00()
    {
        var (pipeline, _) = Build(new SentinelOptions { MaxScanBytes = 100 }, [new FiringDetector()]);

        var result = await pipeline.GetResponseResultAsync(User(200), null, TestContext.Current.CancellationToken);

        var detections = Detections(result);
        var finding = Assert.Single(detections, d => Is(d, Sec00));
        Assert.Equal(Severity.Critical, finding.Severity);
        Assert.Equal(SentinelAction.Quarantine, Assert.IsType<SentinelError.ThreatDetected>(result.Error).Action);
        Assert.Equal("New content is 200 bytes; only the first 100 were scanned. Raise the scan budget (MaxScanBytes, SENTINEL_HOOK_MAX_SCAN_BYTES or SENTINEL_MCP_MAX_SCAN_BYTES) to scan more.", finding.Reason);
    }

    [Fact]
    public async Task AtBudget_NoSec00()
    {
        var (pipeline, _) = Build(new SentinelOptions { MaxScanBytes = 100 }, [new CredentialExposureDetector()]);

        var result = await pipeline.GetResponseResultAsync(User(100), null, TestContext.Current.CancellationToken);

        Assert.True(result.IsSuccess);
    }

    [Fact]
    public async Task Oversize_HeadStillScanned()
    {
        var opts = new SentinelOptions { MaxScanBytes = 100, RedactByDefault = false };
        var (pipeline, _) = Build(opts, [new CredentialExposureDetector()]);
        var text = "key ghp_abcdefghijklmnopqrstuvwxyz0123456789 " + new string('a', 200);

        var result = await pipeline.GetResponseResultAsync([new(ChatRole.User, text)], null, TestContext.Current.CancellationToken);

        var ids = Detections(result).Select(d => d.DetectorId.Value).ToList();
        Assert.Contains("SEC-02", ids, StringComparer.Ordinal);
        Assert.Contains(Sec00, ids, StringComparer.Ordinal);
    }

    [Fact]
    public async Task Oversize_NotAffectedByActionOverridesOrCap()
    {
        var opts = new SentinelOptions { MaxScanBytes = 100 };
        var configurations = new Dictionary<Type, DetectorConfiguration>
        {
            [typeof(FiringDetector)] = new() { SeverityCap = Severity.Low, Action = SentinelAction.Log },
        };
        var (pipeline, _) = Build(opts, [new FiringDetector()], configurations: configurations);

        var result = await pipeline.GetResponseResultAsync(User(200), null, TestContext.Current.CancellationToken);

        var detections = Detections(result);
        var finding = Assert.Single(detections, d => Is(d, Sec00));
        Assert.Equal(Severity.Critical, finding.Severity);
        Assert.Null(finding.ActionOverride);
        var fired = Assert.Single(detections, d => Is(d, "TEST-FIRE"));
        Assert.Equal(Severity.Low, fired.Severity);
    }

    [Fact]
    public async Task OnCriticalLog_Sec00IsLoggedNotBlocked()
    {
        var opts = new SentinelOptions { MaxScanBytes = 100, OnCritical = SentinelAction.Log };
        var (pipeline, audit) = Build(opts, [new FiringDetector()]);

        var result = await pipeline.GetResponseResultAsync(User(200), null, TestContext.Current.CancellationToken);

        Assert.True(result.IsSuccess);
        Assert.Contains(await Entries(audit), e => string.Equals(e.DetectorId, Sec00, StringComparison.Ordinal));
    }

    [Fact]
    public async Task Streaming_OversizeResponse_Blocked()
    {
        var opts = new SentinelOptions { MaxScanBytes = 100 };
        var audit = new RingBufferAuditStore(100);
        var detection = new DetectionPipeline([new FiringDetector()], configurations: null, reviewer: null);
        var pipeline = new SentinelPipeline(new ReplyClient(new string('b', 200)), detection, audit, new InterventionEngine(opts, null), opts);

        var result = await pipeline.GetStreamingResultAsync([new ChatMessage(ChatRole.User, "hi")], null, TestContext.Current.CancellationToken);

        var error = Assert.IsType<SentinelError.ThreatDetected>(result.Error);
        Assert.Contains(error.Detections, d => Is(d, Sec00));
        Assert.Equal(SentinelAction.Quarantine, error.Action);
    }

    // A named pipeline starts from default options, not from the default pipeline's.
    [Fact]
    public void NamedPipeline_StartsFromDefaultMaxScanBytes()
    {
        var services = new ServiceCollection();
        services.AddAISentinel(o => o.MaxScanBytes = 100);
        services.AddAISentinel("strict", o => { });
        using var provider = services.BuildServiceProvider();

        Assert.Equal(100, provider.GetRequiredService<SentinelOptions>().MaxScanBytes);
        Assert.Equal(new SentinelOptions().MaxScanBytes, provider.GetRequiredKeyedService<SentinelOptions>("strict").MaxScanBytes);
    }

    [Fact]
    public async Task NamedPipeline_OwnMaxScanBytesWins()
    {
        var services = new ServiceCollection();
        services.AddAISentinel(o => o.MaxScanBytes = 1_000_000);
        services.AddAISentinel("strict", o => o.MaxScanBytes = 100);
        using var provider = services.BuildServiceProvider();
        var opts = provider.GetRequiredKeyedService<SentinelOptions>("strict");
        var pipeline = new SentinelPipeline(
            new ReplyClient("fine"),
            provider.GetRequiredKeyedService<IDetectionPipeline>("strict"),
            new RingBufferAuditStore(100),
            provider.GetRequiredKeyedService<InterventionEngine>("strict"),
            opts);

        var result = await pipeline.GetResponseResultAsync(User(200), null, TestContext.Current.CancellationToken);

        Assert.Contains(Detections(result), d => Is(d, Sec00));
    }

    [Fact]
    public async Task NoDetectors_OversizeStillReported()
    {
        var (pipeline, _) = Build(new SentinelOptions { MaxScanBytes = 100 });

        var result = await pipeline.GetResponseResultAsync(User(200), null, TestContext.Current.CancellationToken);

        Assert.Contains(Detections(result), d => Is(d, Sec00));
    }
}
