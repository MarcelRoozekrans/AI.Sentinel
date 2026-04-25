using Xunit;
using Microsoft.Extensions.AI;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using AI.Sentinel.Audit;
using AI.Sentinel.Detectors.Hallucination;
using AI.Sentinel.Tests.Helpers;

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
    [InlineData("See arxiv:9999.99999 for details on this topic")]
    [InlineData("This is documented in doi:10.9999/fake.journal.9999")]
    public async Task PhantomCitation_Detected(string text) =>
        Assert.True((await new PhantomCitationDetector(TestOptions.WithFakeEmbeddings()).AnalyzeAsync(Ctx(text), default)).Severity >= Severity.Medium);

    [Fact] public async Task SelfConsistency_ContradictoryNumbers_Detected()
    {
        var text = "The population is 1 million. As I mentioned, the population is 50 million.";
        var r = await new SelfConsistencyDetector(TestOptions.WithFakeEmbeddings()).AnalyzeAsync(Ctx(text), default);
        Assert.True(r.Severity >= Severity.Low);
    }

    [Fact] public async Task AllHallucinationStubDetectors_DoNotThrow()
    {
        IDetector[] detectors = [
            new CrossAgentContradictionDetector(TestOptions.WithFakeEmbeddings()),
            new SourceGroundingDetector(TestOptions.WithFakeEmbeddings()),
            new ConfidenceDecayDetector(TestOptions.WithFakeEmbeddings()),
        ];
        foreach (var d in detectors)
        {
            var r = await d.AnalyzeAsync(Ctx("I think this might be true."), default);
            Assert.NotNull(r);
        }
    }

    // HAL-06: StaleKnowledgeDetector
    [Theory]
    [InlineData("as of today the current ceo of that organization is john smith")]
    [InlineData("right now the price stands at ninety-nine dollars per month subscription")]
    [InlineData("currently the most recent software release adds these new capabilities")]
    public async Task StaleKnowledge_Detected(string text) =>
        Assert.True((await new StaleKnowledgeDetector(TestOptions.WithFakeEmbeddings()).AnalyzeAsync(Ctx(text), default)).Severity >= Severity.Low);

    [Fact] public async Task StaleKnowledge_Clean()
    {
        var r = await new StaleKnowledgeDetector(TestOptions.WithFakeEmbeddings()).AnalyzeAsync(Ctx("x+y=z"), default);
        Assert.Equal(Severity.None, r.Severity);
    }

    // HAL-07: IntraSessionContradictionDetector
    [Fact] public async Task IntraSessionContradiction_Detected()
    {
        var text = "The city has a population of 1,000 people. The GDP is $500 billion driven by 50,000 companies.";
        var r = await new IntraSessionContradictionDetector(TestOptions.WithFakeEmbeddings()).AnalyzeAsync(Ctx(text), default);
        Assert.True(r.Severity >= Severity.Low);
    }

    [Fact] public async Task IntraSessionContradiction_Clean()
    {
        var r = await new IntraSessionContradictionDetector(TestOptions.WithFakeEmbeddings()).AnalyzeAsync(
            Ctx("There are 100 users and we have 200 total accounts."), default);
        Assert.Equal(Severity.None, r.Severity);
    }

    // HAL-08: GroundlessStatisticDetector
    [Fact] public async Task GroundlessStatistic_Detected()
    {
        var text = "seventy-five percent of respondents expressed satisfaction without any cited source";
        var r = await new GroundlessStatisticDetector(TestOptions.WithFakeEmbeddings()).AnalyzeAsync(Ctx(text), default);
        Assert.True(r.Severity >= Severity.Low);
    }

    [Fact] public async Task GroundlessStatistic_WithSource_Clean()
    {
        var r = await new GroundlessStatisticDetector(TestOptions.WithFakeEmbeddings()).AnalyzeAsync(
            Ctx("x+y=z"), default);
        Assert.Equal(Severity.None, r.Severity);
    }

    [Fact] public async Task GroundlessStatistic_NoStat_Clean()
    {
        var r = await new GroundlessStatisticDetector(TestOptions.WithFakeEmbeddings()).AnalyzeAsync(
            Ctx("x+y=z"), default);
        Assert.Equal(Severity.None, r.Severity);
    }

    // HAL-09: UncertaintyPropagationDetector
    [Fact] public async Task UncertaintyPropagation_NoHedging_Clean()
    {
        var r = await new UncertaintyPropagationDetector(TestOptions.WithFakeEmbeddings()).AnalyzeAsync(
            Ctx("The capital of France is Paris."), default);
        Assert.True(r.IsClean);
    }

    [Fact] public async Task UncertaintyPropagation_HedgingOnly_Low()
    {
        var r = await new UncertaintyPropagationDetector(TestOptions.WithFakeEmbeddings()).AnalyzeAsync(
            Ctx("not entirely certain which approach yields optimal outcomes"), default);
        Assert.Equal(Severity.Low, r.Severity);
    }

    [Fact] public async Task UncertaintyPropagation_HedgingPlusAssertion_Medium()
    {
        var r = await new UncertaintyPropagationDetector(TestOptions.WithFakeEmbeddings()).AnalyzeAsync(
            Ctx("I think this might be true, therefore the answer is definitely correct"), default);
        Assert.True(r.Severity >= Severity.Medium);
    }
}
