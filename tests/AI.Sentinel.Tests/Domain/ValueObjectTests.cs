using AI.Sentinel.Domain;
using Xunit;

namespace AI.Sentinel.Tests.Domain;

public class ValueObjectTests
{
    [Fact] public void AgentId_Equality() =>
        Assert.Equal(new AgentId("bot-a"), new AgentId("bot-a"));

    [Fact] public void AgentId_Inequality() =>
        Assert.NotEqual(new AgentId("bot-a"), new AgentId("bot-b"));

    [Fact] public void ThreatRiskScore_Clamps_To_100() =>
        Assert.Equal(100, new ThreatRiskScore(150).Value);

    [Fact] public void ThreatRiskScore_Clamps_To_0() =>
        Assert.Equal(0, new ThreatRiskScore(-10).Value);

    [Fact] public void ThreatRiskScore_Stage_Critical() =>
        Assert.Equal(ThreatStage.Isolate, new ThreatRiskScore(90).Stage);

    [Fact] public void ThreatRiskScore_Stage_Safe() =>
        Assert.Equal(ThreatStage.Safe, new ThreatRiskScore(10).Stage);

    [Fact] public void ThreatRiskScore_Aggregate_WeightedFormula()
    {
        var scores = new[] { new ThreatRiskScore(100), new ThreatRiskScore(50) };
        var result = ThreatRiskScore.Aggregate(scores);
        // max=100, avg=75, weighted = 100*0.6 + 75*0.4 = 60+30 = 90
        Assert.Equal(90, result.Value);
    }

    [Fact] public void ThreatRiskScore_Stage_Boundaries()
    {
        Assert.Equal(ThreatStage.Safe,    new ThreatRiskScore(24).Stage);
        Assert.Equal(ThreatStage.Watch,   new ThreatRiskScore(25).Stage);
        Assert.Equal(ThreatStage.Alert,   new ThreatRiskScore(50).Stage);
        Assert.Equal(ThreatStage.Isolate, new ThreatRiskScore(75).Stage);
    }

    [Fact] public void ThreatRiskScore_Equality()
    {
        Assert.Equal(new ThreatRiskScore(50), new ThreatRiskScore(50));
        Assert.NotEqual(new ThreatRiskScore(50), new ThreatRiskScore(60));
    }

    [Fact] public void AgentId_EmptyString_Throws() =>
        Assert.Throws<ArgumentException>(() => new AgentId(""));
}
