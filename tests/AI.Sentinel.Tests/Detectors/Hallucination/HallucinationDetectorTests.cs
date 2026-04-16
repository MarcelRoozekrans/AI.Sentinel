using Xunit;
using Microsoft.Extensions.AI;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using AI.Sentinel.Audit;
using AI.Sentinel.Detectors.Hallucination;

namespace AI.Sentinel.Tests.Detectors.Hallucination;

public class HallucinationDetectorTests
{
    private static SentinelContext Ctx(string text) => new(
        new AgentId("a"), new AgentId("b"), SessionId.New(),
        new List<ChatMessage> { new(ChatRole.Assistant, text) }, new List<AuditEntry>());

    [Theory]
    [InlineData("See arxiv:9999.99999 for details")]
    [InlineData("doi:10.9999/fake.journal.9999")]
    public async Task PhantomCitation_Detected(string text) =>
        Assert.True((await new PhantomCitationDetector().AnalyzeAsync(Ctx(text), default)).Severity >= Severity.Medium);

    [Fact] public async Task SelfConsistency_ContradictoryNumbers_Detected()
    {
        var text = "The population is 1 million. As I mentioned, the population is 50 million.";
        var r = await new SelfConsistencyDetector().AnalyzeAsync(Ctx(text), default);
        Assert.True(r.Severity >= Severity.Low);
    }
}
