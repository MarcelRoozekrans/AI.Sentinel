using Xunit;
using Microsoft.Extensions.AI;
using AI.Sentinel;
using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using AI.Sentinel.Detectors.Security;
using ZeroAlloc.Serialisation;

namespace AI.Sentinel.Tests.Detectors.Security;

public class OutputSchemaDetectorTests
{
    private static SentinelContext Ctx(params ChatMessage[] msgs) => new(
        new AgentId("a"), new AgentId("b"), SessionId.New(),
        msgs.ToList(),
        new List<AuditEntry>());

    private static OutputSchemaDetector Build(SentinelOptions opts) =>
        new(opts, new SerializerDispatcher());

    [Fact]
    public async Task ExpectedTypeNotSet_ReturnsClean()
    {
        var d = Build(new SentinelOptions());
        var r = await d.AnalyzeAsync(Ctx(new ChatMessage(ChatRole.Assistant, "anything")), default);
        Assert.Equal(Severity.None, r.Severity);
    }

    [Fact]
    public async Task NoAssistantMessage_ReturnsClean()
    {
        var opts = new SentinelOptions { ExpectedResponseType = typeof(WeatherResponse) };
        var d = Build(opts);
        var r = await d.AnalyzeAsync(Ctx(new ChatMessage(ChatRole.User, "hi")), default);
        Assert.Equal(Severity.None, r.Severity);
    }

    [Fact]
    public async Task ValidJson_MatchesType_ReturnsClean()
    {
        var opts = new SentinelOptions { ExpectedResponseType = typeof(WeatherResponse) };
        var d = Build(opts);
        var r = await d.AnalyzeAsync(
            Ctx(new ChatMessage(ChatRole.Assistant, """{"city":"Amsterdam","temperatureC":12}""")),
            default);
        Assert.Equal(Severity.None, r.Severity);
    }

    [Fact]
    public async Task MalformedJson_ReturnsHigh()
    {
        var opts = new SentinelOptions { ExpectedResponseType = typeof(WeatherResponse) };
        var d = Build(opts);
        var r = await d.AnalyzeAsync(
            Ctx(new ChatMessage(ChatRole.Assistant, "{not valid json")),
            default);
        Assert.Equal(Severity.High, r.Severity);
    }

    [Fact]
    public async Task MissingRequiredProperty_ReturnsHigh()
    {
        var opts = new SentinelOptions { ExpectedResponseType = typeof(WeatherResponse) };
        var d = Build(opts);
        var r = await d.AnalyzeAsync(
            Ctx(new ChatMessage(ChatRole.Assistant, """{"city":"Amsterdam"}""")),
            default);
        Assert.Equal(Severity.High, r.Severity);
    }

    [Fact]
    public async Task WrappedInCodeFence_IsExtracted()
    {
        var opts = new SentinelOptions { ExpectedResponseType = typeof(WeatherResponse) };
        var d = Build(opts);
        var fenced = "```json\n{\"city\":\"NYC\",\"temperatureC\":5}\n```";
        var r = await d.AnalyzeAsync(
            Ctx(new ChatMessage(ChatRole.Assistant, fenced)),
            default);
        Assert.Equal(Severity.None, r.Severity);
    }

    [Fact]
    public async Task NullDeserialization_ReturnsHigh()
    {
        var opts = new SentinelOptions { ExpectedResponseType = typeof(WeatherResponse) };
        var d = Build(opts);
        var r = await d.AnalyzeAsync(
            Ctx(new ChatMessage(ChatRole.Assistant, "null")),
            default);
        Assert.Equal(Severity.High, r.Severity);
    }
}
