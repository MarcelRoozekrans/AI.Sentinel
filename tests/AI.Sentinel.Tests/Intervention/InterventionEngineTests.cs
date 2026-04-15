using Xunit;
using AI.Sentinel;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using AI.Sentinel.Intervention;

public class InterventionEngineTests
{
    private static PipelineResult CleanResult() =>
        new(ThreatRiskScore.Zero, new List<DetectionResult>());

    private static PipelineResult CriticalResult() =>
        new(new ThreatRiskScore(90),
            new List<DetectionResult> {
                DetectionResult.WithSeverity(new DetectorId("SEC-01"), Severity.Critical, "injection")
            });

    [Fact] public void CleanResult_DoesNotThrow()
    {
        var opts = new SentinelOptions();
        var engine = new InterventionEngine(opts, mediator: null);
        engine.Apply(CleanResult());
    }

    [Fact] public void CriticalResult_WithQuarantineAction_Throws()
    {
        var opts = new SentinelOptions { OnCritical = SentinelAction.Quarantine };
        var engine = new InterventionEngine(opts, mediator: null);
        Assert.Throws<SentinelException>(() => engine.Apply(CriticalResult()));
    }

    [Fact] public void CriticalResult_WithLogAction_DoesNotThrow()
    {
        var opts = new SentinelOptions { OnCritical = SentinelAction.Log };
        var engine = new InterventionEngine(opts, mediator: null);
        engine.Apply(CriticalResult());
    }
}
