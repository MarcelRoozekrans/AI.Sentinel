using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using Microsoft.Extensions.AI;
using Xunit;

namespace AI.Sentinel.Tests.Detection;

/// <summary>A detector that throws must not take the scan with it. Once the CLIs could configure an
/// embedding endpoint, an unreachable Ollama or a 429 propagated out of the pipeline to the hook's
/// top-level handler, which exits 1 — documented as "tool failure, not a Sentinel block". The prompt
/// then proceeded completely unscanned, including the rule-based detectors that never needed the
/// network. Failing open on every control because one dependency is down is the worst outcome
/// available.</summary>
public class DetectorFailureIsolationTests
{
    private static SentinelContext Context() => new(
        new AgentId("a"), new AgentId("b"), SessionId.New(),
        new List<ChatMessage> { new(ChatRole.User, "text") },
        new List<AuditEntry>());

    private sealed class ThrowingDetector : IDetector
    {
        public DetectorId Id => new("TST-THROW");
        public DetectorCategory Category => DetectorCategory.Security;
        public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct) =>
            throw new HttpRequestException("embedding endpoint unreachable");
    }

    private sealed class AsyncThrowingDetector : IDetector
    {
        public DetectorId Id => new("TST-THROW-ASYNC");
        public DetectorCategory Category => DetectorCategory.Security;
        public async ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
        {
            await Task.Yield();
            throw new HttpRequestException("embedding endpoint returned 429");
        }
    }

    private sealed class FiringDetector : IDetector
    {
        public DetectorId Id => new("TST-FIRES");
        public DetectorCategory Category => DetectorCategory.Security;
        public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct) =>
            ValueTask.FromResult(DetectionResult.WithSeverity(Id, Severity.Critical, "rule-based hit"));
    }

    [Fact]
    public async Task ASynchronouslyThrowingDetector_DoesNotFailTheScan()
    {
        var pipeline = new DetectionPipeline(
            [new ThrowingDetector(), new FiringDetector()], configurations: null, escalationClient: null);

        var result = await pipeline.RunAsync(Context(), TestContext.Current.CancellationToken);

        Assert.Contains(result.Detections, d => string.Equals(d.DetectorId.Value, "TST-FIRES", StringComparison.Ordinal));
    }

    [Fact]
    public async Task AnAsynchronouslyThrowingDetector_DoesNotFailTheScan()
    {
        var pipeline = new DetectionPipeline(
            [new AsyncThrowingDetector(), new FiringDetector()], configurations: null, escalationClient: null);

        var result = await pipeline.RunAsync(Context(), TestContext.Current.CancellationToken);

        Assert.Contains(result.Detections, d => string.Equals(d.DetectorId.Value, "TST-FIRES", StringComparison.Ordinal));
    }

    /// <summary>Degrading must not be silent — the operator has to learn the control is down.</summary>
    [Fact]
    public async Task AFailingDetector_IsReported()
    {
        var reported = new List<string>();
        var pipeline = new DetectionPipeline(
            [new ThrowingDetector(), new FiringDetector()],
            configurations: null,
            escalationClient: null,
            logger: null,
            onDetectorFailure: reported.Add);

        await pipeline.RunAsync(Context(), TestContext.Current.CancellationToken);

        Assert.Single(reported);
        Assert.Contains("TST-THROW", reported[0], StringComparison.Ordinal);
    }

    /// <summary>Cancellation is the caller's intent, not a detector fault: it must propagate rather
    /// than be converted into a Clean result that makes an abandoned scan look successful.</summary>
    [Fact]
    public async Task ACancelledDetector_PropagatesRatherThanReportingClean()
    {
        var pipeline = new DetectionPipeline(
            [new CancellingDetector(), new FiringDetector()], configurations: null, escalationClient: null);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await pipeline.RunAsync(Context(), TestContext.Current.CancellationToken));
    }

    private sealed class CancellingDetector : IDetector
    {
        public DetectorId Id => new("TST-CANCEL");
        public DetectorCategory Category => DetectorCategory.Security;
        public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct) =>
            throw new OperationCanceledException();
    }
}
