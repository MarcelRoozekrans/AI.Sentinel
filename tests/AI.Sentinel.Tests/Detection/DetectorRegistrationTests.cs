using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using Xunit;

namespace AI.Sentinel.Tests.Detection;

/// <summary>A <c>SentinelOptions.DetectorRegistration</c> holds exactly one of a detector type and a factory.
/// RegisterUserDetectors relies on that: a registration with neither would otherwise be dropped silently.</summary>
public class DetectorRegistrationTests
{
    [Fact]
    public void A_registration_with_neither_a_type_nor_a_factory_is_refused()
    {
        // Red: remove the exactly-one check from the DetectorRegistration constructor: no exception is thrown.
        var ex = Assert.Throws<ArgumentException>(
            () => new SentinelOptions.DetectorRegistration(detectorType: null, factory: null));
        Assert.Equal("detectorType", ex.ParamName);
    }

    [Fact]
    public void A_registration_with_both_a_type_and_a_factory_is_refused()
    {
        // Red: check only that one of the two is set, not that exactly one is: no exception is thrown.
        Assert.Throws<ArgumentException>(
            () => new SentinelOptions.DetectorRegistration(typeof(NoOpDetector), _ => new NoOpDetector()));
    }

    private sealed class NoOpDetector : IDetector
    {
        private static readonly DetectorId NoOpId = new("NOOP-01");

        public DetectorId Id => NoOpId;

        public DetectorCategory Category => DetectorCategory.Security;

        public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct) =>
            ValueTask.FromResult(DetectionResult.Clean(NoOpId));
    }
}
