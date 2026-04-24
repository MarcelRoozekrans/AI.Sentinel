using Xunit;
using Microsoft.Extensions.AI;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using AI.Sentinel.Audit;
using AI.Sentinel.Detectors.Operational;

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

    [Fact] public async Task AllOperationalStubDetectors_DoNotThrow()
    {
        IDetector[] stubs = [
            new ContextCollapseDetector(),
            new AgentProbingDetector(),
            new QueryIntentDetector(),
            new ResponseCoherenceDetector(),
            new SemanticRepetitionDetector(),
            new PersonaDriftDetector(),
            new SycophancyDetector(),
        ];
        foreach (var d in stubs)
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

    // OPS-10: WaitingForContextDetector
    [Fact] public async Task WaitingForContext_ShortUserMsg_Clean()
    {
        var messages = new List<ChatMessage>
        {
            new(ChatRole.User,      "Help"),
            new(ChatRole.Assistant, "Could you clarify what you need help with?"),
        };
        var r = await new WaitingForContextDetector().AnalyzeAsync(CtxMessages(messages), default);
        Assert.True(r.IsClean);
    }

    [Fact] public async Task WaitingForContext_LongUserSelfContained_Low()
    {
        var messages = new List<ChatMessage>
        {
            new(ChatRole.User,      "Please write me a complete C# class that implements a binary search tree with insert, delete, and find methods including unit tests."),
            new(ChatRole.Assistant, "Could you please provide more details about what you need?"),
        };
        var r = await new WaitingForContextDetector().AnalyzeAsync(CtxMessages(messages), default);
        Assert.True(r.Severity >= Severity.Low);
    }

    [Fact] public async Task WaitingForContext_MultipleStalls_Medium()
    {
        var messages = new List<ChatMessage>
        {
            new(ChatRole.User,      "Please write me a complete C# class that implements a binary search tree with insert, delete, and find methods including unit tests."),
            new(ChatRole.Assistant, "Could you clarify what you need? Please provide more information. Could you specify the requirements?"),
        };
        var r = await new WaitingForContextDetector().AnalyzeAsync(CtxMessages(messages), default);
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
}
