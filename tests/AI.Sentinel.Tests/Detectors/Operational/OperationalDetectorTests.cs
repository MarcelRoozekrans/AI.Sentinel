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
}
