using Xunit;
using Microsoft.Extensions.AI;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using AI.Sentinel.Audit;
using AI.Sentinel.Detectors.Operational;
using AI.Sentinel.Tests.Helpers;

namespace AI.Sentinel.Tests.Detectors.Operational;

public class OperationalDetectorTests
{
    private static SentinelContext Ctx(string text) => new(
        new AgentId("a"), new AgentId("b"), SessionId.New(),
        new List<ChatMessage> { new(ChatRole.Assistant, text) }, new List<AuditEntry>());

    private static SentinelContext CtxMessages(IReadOnlyList<ChatMessage> messages) => new(
        new AgentId("a"), new AgentId("b"), SessionId.New(),
        messages, new List<AuditEntry>());

    [Fact] public async Task BlankResponse_Detected() =>
        Assert.True((await new BlankResponseDetector().AnalyzeAsync(Ctx("   "), default)).Severity >= Severity.Medium);

    [Fact] public async Task RepetitionLoop_Detected()
    {
        var repeated = string.Join(". ", Enumerable.Repeat("I cannot help with that", 5));
        Assert.True((await new RepetitionLoopDetector().AnalyzeAsync(Ctx(repeated), default)).Severity >= Severity.Medium);
    }

    [Fact] public async Task PlaceholderText_Detected() =>
        Assert.True((await new PlaceholderTextDetector().AnalyzeAsync(Ctx("TODO: implement this"), default)).Severity >= Severity.Low);

    [Fact] public async Task IncompleteCodeBlock_Detected() =>
        Assert.True((await new IncompleteCodeBlockDetector().AnalyzeAsync(Ctx("```python\ndef foo():"), default)).Severity >= Severity.Medium);

    [Fact] public async Task CleanResponse_NoFlags()
    {
        IDetector[] all = [
            new BlankResponseDetector(), new RepetitionLoopDetector(),
            new PlaceholderTextDetector(), new IncompleteCodeBlockDetector(),
        ];
        foreach (var d in all)
            Assert.Equal(Severity.None, (await d.AnalyzeAsync(Ctx("The answer is 42."), default)).Severity);
    }

    [Fact] public async Task AllOperationalSemanticDetectors_DoNotThrow()
    {
        IDetector[] detectors = [
            new ContextCollapseDetector(TestOptions.WithFakeEmbeddings()),
            new AgentProbingDetector(TestOptions.WithFakeEmbeddings()),
            new QueryIntentDetector(TestOptions.WithFakeEmbeddings()),
            new ResponseCoherenceDetector(TestOptions.WithFakeEmbeddings()),
            new SemanticRepetitionDetector(TestOptions.WithFakeEmbeddings()),
            new PersonaDriftDetector(TestOptions.WithFakeEmbeddings()),
            new SycophancyDetector(TestOptions.WithFakeEmbeddings()),
            new WaitingForContextDetector(TestOptions.WithFakeEmbeddings()),
        ];
        foreach (var d in detectors)
        {
            var r = await d.AnalyzeAsync(Ctx("What did we discuss earlier?"), default);
            Assert.NotNull(r);
        }
    }

    // OPS-15: WrongLanguageDetector
    [Fact] public async Task WrongLanguage_LatinUserNonLatinAssistant_Detected()
    {
        var messages = new List<ChatMessage>
        {
            new(ChatRole.User, "What is the capital of France? Please answer in English."),
            new(ChatRole.Assistant, "巴黎是法国的首都，也是最大的城市。它以埃菲尔铁塔和卢浮宫等著名景点而闻名。"),
        };
        var r = await new WrongLanguageDetector().AnalyzeAsync(CtxMessages(messages), default);
        Assert.True(r.Severity >= Severity.Medium);
    }

    [Fact] public async Task WrongLanguage_SameScript_Clean()
    {
        var messages = new List<ChatMessage>
        {
            new(ChatRole.User, "What is the capital of France?"),
            new(ChatRole.Assistant, "The capital of France is Paris, a major European city."),
        };
        var r = await new WrongLanguageDetector().AnalyzeAsync(CtxMessages(messages), default);
        Assert.Equal(Severity.None, r.Severity);
    }

    [Fact] public async Task WrongLanguage_ShortMessage_Skipped()
    {
        var messages = new List<ChatMessage>
        {
            new(ChatRole.User, "Hi"),
            new(ChatRole.Assistant, "你好"),
        };
        var r = await new WrongLanguageDetector().AnalyzeAsync(CtxMessages(messages), default);
        Assert.Equal(Severity.None, r.Severity);
    }

    [Fact] public async Task TruncatedOutput_MidSentence_Medium()
    {
        var r = await new TruncatedOutputDetector().AnalyzeAsync(
            Ctx("The model was running fine then it suddenly"), default);
        Assert.True(r.Severity >= Severity.Medium);
    }

    [Fact] public async Task TruncatedOutput_OpenCodeFence_Low()
    {
        var r = await new TruncatedOutputDetector().AnalyzeAsync(
            Ctx("Here is the code:\n```csharp\nvar x = 1;"), default);
        Assert.Equal(Severity.Low, r.Severity);
    }

    [Fact] public async Task TruncatedOutput_CompleteResponse_Clean()
    {
        var r = await new TruncatedOutputDetector().AnalyzeAsync(
            Ctx("The answer is 42."), default);
        Assert.True(r.IsClean);
    }

    [Fact] public async Task TruncatedOutput_Ellipsis_Low()
    {
        var r = await new TruncatedOutputDetector().AnalyzeAsync(
            Ctx("The model was processing the request..."), default);
        Assert.Equal(Severity.Low, r.Severity);
    }

    // OPS-10: WaitingForContextDetector
    [Fact] public async Task WaitingForContext_ShortUserMsg_Clean()
    {
        var messages = new List<ChatMessage>
        {
            new(ChatRole.User,      "What is 2+2?"),
            new(ChatRole.Assistant, "The capital of France is Paris."),
        };
        var r = await new WaitingForContextDetector(TestOptions.WithFakeEmbeddings()).AnalyzeAsync(CtxMessages(messages), default);
        Assert.True(r.IsClean);
    }

    [Fact] public async Task WaitingForContext_ExactLowPhrase_Detected()
    {
        var r = await new WaitingForContextDetector(TestOptions.WithFakeEmbeddings())
            .AnalyzeAsync(Ctx("Please provide more details about what you need"), default);
        Assert.True(r.Severity >= Severity.Low);
    }

    [Fact] public async Task WaitingForContext_ExactMediumPhrase_AtLeastLow()
    {
        var r = await new WaitingForContextDetector(TestOptions.WithFakeEmbeddings())
            .AnalyzeAsync(Ctx("Please provide more details and could you also clarify what you mean by that"), default);
        Assert.True(r.Severity >= Severity.Medium);
    }

    // OPS-11: UnboundedConsumptionDetector
    [Fact] public async Task UnboundedConsumption_SmallResponse_Clean()
    {
        var messages = new List<ChatMessage>
        {
            new(ChatRole.User,      "What is 2+2?"),
            new(ChatRole.Assistant, "The answer is 4."),
        };
        var r = await new UnboundedConsumptionDetector().AnalyzeAsync(CtxMessages(messages), default);
        Assert.True(r.IsClean);
    }

    [Fact] public async Task UnboundedConsumption_LargeAbsolute_Low()
    {
        var messages = new List<ChatMessage>
        {
            new(ChatRole.User,      "Write me something."),
            new(ChatRole.Assistant, new string('a', 6_000)),
        };
        var r = await new UnboundedConsumptionDetector().AnalyzeAsync(CtxMessages(messages), default);
        Assert.True(r.Severity >= Severity.Low);
    }

    [Fact] public async Task UnboundedConsumption_HighRatio_Medium()
    {
        var messages = new List<ChatMessage>
        {
            new(ChatRole.User,      "Hi"),
            new(ChatRole.Assistant, new string('a', 16_000)),
        };
        var r = await new UnboundedConsumptionDetector().AnalyzeAsync(CtxMessages(messages), default);
        Assert.True(r.Severity >= Severity.Medium);
    }

    [Fact] public async Task UnboundedConsumption_ExtremeResponse_High()
    {
        var messages = new List<ChatMessage>
        {
            new(ChatRole.User,      "Summarize this."),
            new(ChatRole.Assistant, new string('a', 51_000)),
        };
        var r = await new UnboundedConsumptionDetector().AnalyzeAsync(CtxMessages(messages), default);
        Assert.True(r.Severity >= Severity.High);
    }

    [Fact] public async Task UnboundedConsumption_NoUserMessage_Clean()
    {
        var messages = new List<ChatMessage>
        {
            new(ChatRole.Assistant, "The capital of France is Paris."),
        };
        var r = await new UnboundedConsumptionDetector().AnalyzeAsync(CtxMessages(messages), default);
        Assert.True(r.IsClean);
    }

    // OPS-05: ContextCollapseDetector
    [Fact] public async Task ContextCollapse_ExactLowPhrase_Detected()
    {
        var r = await new ContextCollapseDetector(TestOptions.WithFakeEmbeddings())
            .AnalyzeAsync(Ctx("I apologize but I have forgotten the details from earlier in our conversation"), default);
        Assert.True(r.Severity >= Severity.Low);
    }

    // OPS-06: AgentProbingDetector
    [Fact] public async Task AgentProbing_ExactLowPhrase_Detected()
    {
        var r = await new AgentProbingDetector(TestOptions.WithFakeEmbeddings())
            .AnalyzeAsync(Ctx("What are your capabilities and what can you access in this environment"), default);
        Assert.True(r.Severity >= Severity.Low);
    }

    // OPS-07: QueryIntentDetector
    [Fact] public async Task QueryIntent_ExactLowPhrase_Detected()
    {
        var r = await new QueryIntentDetector(TestOptions.WithFakeEmbeddings())
            .AnalyzeAsync(Ctx("Could you clarify the intent behind your question"), default);
        Assert.True(r.Severity >= Severity.Low);
    }

    // OPS-08: ResponseCoherenceDetector
    [Fact] public async Task ResponseCoherence_ExactLowPhrase_Detected()
    {
        var r = await new ResponseCoherenceDetector(TestOptions.WithFakeEmbeddings())
            .AnalyzeAsync(Ctx("There is some inconsistency between this response and the earlier context"), default);
        Assert.True(r.Severity >= Severity.Low);
    }

    // OPS-12: SemanticRepetitionDetector
    [Fact] public async Task SemanticRepetition_ExactLowPhrase_Detected()
    {
        var r = await new SemanticRepetitionDetector(TestOptions.WithFakeEmbeddings())
            .AnalyzeAsync(Ctx("I have touched on this topic already in a prior response"), default);
        Assert.True(r.Severity >= Severity.Low);
    }

    // OPS-13: PersonaDriftDetector
    [Fact] public async Task PersonaDrift_ExactLowPhrase_Detected()
    {
        var r = await new PersonaDriftDetector(TestOptions.WithFakeEmbeddings())
            .AnalyzeAsync(Ctx("I seem to be responding in a way that differs from my original instructions"), default);
        Assert.True(r.Severity >= Severity.Low);
    }

    // OPS-14: SycophancyDetector
    [Fact] public async Task Sycophancy_ExactLowPhrase_Detected()
    {
        var r = await new SycophancyDetector(TestOptions.WithFakeEmbeddings())
            .AnalyzeAsync(Ctx("Great question, I love how you think about this topic"), default);
        Assert.True(r.Severity >= Severity.Low);
    }
}
