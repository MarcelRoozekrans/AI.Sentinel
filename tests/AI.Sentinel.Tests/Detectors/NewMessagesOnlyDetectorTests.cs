using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using AI.Sentinel.Detectors.Operational;
using AI.Sentinel.Detectors.Security;
using AI.Sentinel.Domain;
using Microsoft.Extensions.AI;
using Xunit;

namespace AI.Sentinel.Tests.Detectors;

// #439. A detector that judges content reads only the new messages: the same text is Clean as history and a
// finding as a new message, so a tool loop does not report round 1's content again on every later round trip.
public class NewMessagesOnlyDetectorTests
{
    private const string Key = "password=hunter2secretvalue";
    private const string Tags = "\U000E0041\U000E0042\U000E0043\U000E0044";
    private const string Base64 = "Here is the payload: qX7vK2mZp9RtLw4JhB6NcF8sYdQe1AgU3TiO5WxV0zPrMkHn";
    private const string Chinese = "巴黎是法国的首都，也是最大的城市。它以埃菲尔铁塔和卢浮宫等著名景点而闻名。";
    private const string English = "What is the capital of France? Please answer in English.";

    private static readonly string Repeated = string.Join(". ", Enumerable.Repeat("I cannot help with that", 5));

    private static SentinelContext Ctx(IReadOnlyList<ChatMessage> messages, int newFrom) => new(
        new AgentId("a"), new AgentId("b"), SessionId.New(), messages, new List<AuditEntry>())
    { NewMessagesFrom = newFrom };

    private static ChatMessage[] HistoryThenNew(ChatRole role, string history, string fresh) =>
    [
        new(role, history),
        new(ChatRole.Assistant, "ok."),
        new(role, fresh),
    ];

    public static TheoryData<string, ChatRole, string, string> Cases => new()
    {
        { nameof(CredentialExposureDetector), ChatRole.Tool, Key, "nothing here" },
        { nameof(PiiLeakageDetector), ChatRole.User, "mail me at jane.doe@example.org", "nothing here" },
        { nameof(PlaceholderTextDetector), ChatRole.Assistant, "TODO: implement this", "Done and dusted." },
        { nameof(RepetitionLoopDetector), ChatRole.Assistant, Repeated, "Done and dusted." },
        { nameof(AdversarialUnicodeDetector), ChatRole.User, "hidden" + Tags, "plain text" },
        { nameof(EntropyCovertChannelDetector), ChatRole.User, Base64, "plain text" },
        { nameof(IncompleteCodeBlockDetector), ChatRole.Assistant, "```python\ndef foo():", "Done and dusted." },
        { nameof(TruncatedOutputDetector), ChatRole.Assistant, "```python\nx = 1", "Done and dusted." },
    };

    private static IDetector Create(string name) => name switch
    {
        nameof(CredentialExposureDetector) => new CredentialExposureDetector(),
        nameof(PiiLeakageDetector) => new PiiLeakageDetector(),
        nameof(PlaceholderTextDetector) => new PlaceholderTextDetector(),
        nameof(RepetitionLoopDetector) => new RepetitionLoopDetector(),
        nameof(AdversarialUnicodeDetector) => new AdversarialUnicodeDetector(),
        nameof(EntropyCovertChannelDetector) => new EntropyCovertChannelDetector(),
        nameof(IncompleteCodeBlockDetector) => new IncompleteCodeBlockDetector(),
        nameof(TruncatedOutputDetector) => new TruncatedOutputDetector(),
        _ => throw new ArgumentOutOfRangeException(nameof(name)),
    };

    private static ChatMessage Message(ChatRole role, string text) => role == ChatRole.Tool
        ? new ChatMessage(ChatRole.Tool, [new FunctionResultContent("c1", text)])
        : new ChatMessage(role, text);

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task Detector_IgnoresHistory(string name, ChatRole role, string trigger, string clean)
    {
        var messages = new[] { Message(role, trigger), new ChatMessage(ChatRole.Assistant, "ok."), Message(role, clean) };

        var r = await Create(name).AnalyzeAsync(Ctx(messages, newFrom: 2), TestContext.Current.CancellationToken);

        Assert.True(r.IsClean, $"{name} judged the history");
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task Detector_FlagsNewMessage(string name, ChatRole role, string trigger, string clean)
    {
        var messages = new[] { Message(role, clean), new ChatMessage(ChatRole.Assistant, "ok."), Message(role, trigger) };

        var r = await Create(name).AnalyzeAsync(Ctx(messages, newFrom: 2), TestContext.Current.CancellationToken);

        Assert.False(r.IsClean, $"{name} missed the new message");
    }

    [Fact]
    public async Task WrongLanguage_IgnoresAMismatchInHistory()
    {
        var messages = new ChatMessage[]
        {
            new(ChatRole.User, English), new(ChatRole.Assistant, Chinese),
            new(ChatRole.User, English), new(ChatRole.Assistant, "The capital of France is Paris, a major city."),
        };

        var r = await new WrongLanguageDetector().AnalyzeAsync(Ctx(messages, newFrom: 2), TestContext.Current.CancellationToken);

        Assert.True(r.IsClean);
    }

    [Fact]
    public async Task WrongLanguage_FlagsAMismatchInTheNewMessages()
    {
        var messages = new ChatMessage[]
        {
            new(ChatRole.User, English), new(ChatRole.Assistant, "The capital of France is Paris, a major city."),
            new(ChatRole.User, English), new(ChatRole.Assistant, Chinese),
        };

        var r = await new WrongLanguageDetector().AnalyzeAsync(Ctx(messages, newFrom: 2), TestContext.Current.CancellationToken);

        Assert.False(r.IsClean);
    }
}
