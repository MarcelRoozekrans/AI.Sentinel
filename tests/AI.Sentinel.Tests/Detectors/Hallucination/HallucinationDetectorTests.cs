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

    private static SentinelContext CtxMessages(IReadOnlyList<ChatMessage> messages) => new(
        new AgentId("a"), new AgentId("b"), SessionId.New(),
        messages, new List<AuditEntry>());

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

    [Fact] public async Task AllHallucinationStubDetectors_DoNotThrow()
    {
        IDetector[] stubs = [
            new CrossAgentContradictionDetector(),
            new SourceGroundingDetector(),
            new ConfidenceDecayDetector(),
        ];
        foreach (var d in stubs)
        {
            var r = await d.AnalyzeAsync(Ctx("I think this might be true."), default);
            Assert.NotNull(r);
        }
    }

    // HAL-06: StaleKnowledgeDetector
    [Theory]
    [InlineData("As of today, the current CEO is John Smith.")]
    [InlineData("The latest version supports this feature.")]
    [InlineData("Right now the price is $99.")]
    public async Task StaleKnowledge_Detected(string text) =>
        Assert.True((await new StaleKnowledgeDetector().AnalyzeAsync(Ctx(text), default)).Severity >= Severity.Low);

    [Fact] public async Task StaleKnowledge_Clean()
    {
        var r = await new StaleKnowledgeDetector().AnalyzeAsync(Ctx("This feature was introduced in version 3.0."), default);
        Assert.Equal(Severity.None, r.Severity);
    }

    // HAL-07: IntraSessionContradictionDetector
    [Fact] public async Task IntraSessionContradiction_Detected()
    {
        var messages = new List<ChatMessage>
        {
            new(ChatRole.User, "Tell me about the city."),
            new(ChatRole.Assistant, "The city has a population of 1,000 people."),
            new(ChatRole.User, "And the economy?"),
            new(ChatRole.Assistant, "The GDP is $500 billion, driven by 50,000 companies."),
        };
        var r = await new IntraSessionContradictionDetector().AnalyzeAsync(CtxMessages(messages), default);
        Assert.True(r.Severity >= Severity.Low);
    }

    [Fact] public async Task IntraSessionContradiction_Clean()
    {
        var messages = new List<ChatMessage>
        {
            new(ChatRole.User, "What are the stats?"),
            new(ChatRole.Assistant, "There are 100 users."),
            new(ChatRole.User, "More?"),
            new(ChatRole.Assistant, "We have 200 total accounts."),
        };
        var r = await new IntraSessionContradictionDetector().AnalyzeAsync(CtxMessages(messages), default);
        Assert.Equal(Severity.None, r.Severity);
    }

    // HAL-08: GroundlessStatisticDetector
    [Fact] public async Task GroundlessStatistic_Detected()
    {
        var text = "75% of users are satisfied with this approach.";
        var r = await new GroundlessStatisticDetector().AnalyzeAsync(Ctx(text), default);
        Assert.True(r.Severity >= Severity.Low);
    }

    [Fact] public async Task GroundlessStatistic_WithSource_Clean()
    {
        var text = "According to a 2023 survey, 75% of users are satisfied with this approach.";
        var r = await new GroundlessStatisticDetector().AnalyzeAsync(Ctx(text), default);
        Assert.Equal(Severity.None, r.Severity);
    }

    [Fact] public async Task GroundlessStatistic_NoStat_Clean()
    {
        var r = await new GroundlessStatisticDetector().AnalyzeAsync(Ctx("Most users prefer the new interface."), default);
        Assert.Equal(Severity.None, r.Severity);
    }
}
