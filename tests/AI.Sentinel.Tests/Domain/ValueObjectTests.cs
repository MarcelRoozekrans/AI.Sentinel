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
}
