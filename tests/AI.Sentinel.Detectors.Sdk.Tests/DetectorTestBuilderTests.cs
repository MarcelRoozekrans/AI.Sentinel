using AI.Sentinel.Detection;
using AI.Sentinel.Detectors.Sdk;
using AI.Sentinel.Domain;
using Xunit;

namespace AI.Sentinel.Detectors.Sdk.Tests;

public class DetectorTestBuilderTests
{
    private sealed class StubDetector(Severity severity, string id = "TEST-01") : IDetector
    {
        private readonly DetectorId _id = new(id);
        public DetectorId Id => _id;
        public DetectorCategory Category => DetectorCategory.Operational;
        public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
            => ValueTask.FromResult(severity == Severity.None
                ? DetectionResult.Clean(_id)
                : DetectionResult.WithSeverity(_id, severity, "stub"));
    }

    [Fact]
    public async Task RunAsync_WithDetectorInstance_ReturnsResult()
    {
        var detector = new StubDetector(Severity.High);

        var result = await new DetectorTestBuilder()
            .WithDetector(detector)
            .RunAsync();

        Assert.Equal(Severity.High, result.Severity);
        Assert.Equal("TEST-01", result.DetectorId.Value, StringComparer.Ordinal);
    }

    [Fact]
    public async Task RunAsync_WithoutDetector_ThrowsInvalidOperationException()
    {
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => new DetectorTestBuilder().RunAsync());

        Assert.Contains("WithDetector", ex.Message, StringComparison.Ordinal);
    }
}
