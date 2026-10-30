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

    // OPS-15 pairs the last user and the last assistant message, a property of the whole conversation. On the
    // request leg the assistant message is history and only the user turn is new.
    [Fact]
    public async Task WrongLanguage_RequestLegShape_FlagsAHistoryReplyAgainstTheNewUserTurn()
    {
        var messages = new ChatMessage[]
        {
            new(ChatRole.User, English), new(ChatRole.Assistant, Chinese), new(ChatRole.User, English),
        };

        var r = await new WrongLanguageDetector().AnalyzeAsync(Ctx(messages, newFrom: 2), TestContext.Current.CancellationToken);

        Assert.False(r.IsClean);
    }

    [Fact]
    public async Task WrongLanguage_ReadsOnlyTheCutOfALargeMessage()
    {
        // 33 CJK characters are 99 bytes, inside the 100-byte budget; the megabyte of Latin after them is not read.
        var reply = new string('巴', 33) + new string('a', 1_000_000);
        var messages = new ChatMessage[] { new(ChatRole.User, English), new(ChatRole.Assistant, reply) };
        var cut = new SentinelContext(new AgentId("a"), new AgentId("b"), SessionId.New(), messages, new List<AuditEntry>()) { MaxScanBytes = 100 };
        var uncut = Ctx(messages, newFrom: 0);

        var detector = new WrongLanguageDetector();

        Assert.False((await detector.AnalyzeAsync(cut, TestContext.Current.CancellationToken)).IsClean);
        Assert.True((await detector.AnalyzeAsync(uncut, TestContext.Current.CancellationToken)).IsClean);
    }

    // Only the last user and the last assistant message are paired; an earlier pair in another script is not read.
    [Fact]
    public async Task WrongLanguage_PairsOnlyTheLastUserAndAssistantMessages()
    {
        var messages = new ChatMessage[]
        {
            new(ChatRole.User, English), new(ChatRole.Assistant, Chinese),
            new(ChatRole.User, English), new(ChatRole.Assistant, "Paris is the capital and largest city of France."),
        };

        var r = await new WrongLanguageDetector().AnalyzeAsync(Ctx(messages, newFrom: 3), TestContext.Current.CancellationToken);

        Assert.True(r.IsClean);
    }

    // Past the scan budget the view ends at the cut, so a split fence or sentence is the cut's, not the response's.
    [Theory]
    [InlineData(nameof(TruncatedOutputDetector))]
    [InlineData(nameof(IncompleteCodeBlockDetector))]
    public async Task FenceAndTailChecks_SkippedPastTheScanBudget(string name)
    {
        var reply = "Here is the code:\n```python\nx = 1\n```\nThat is all.";
        var messages = new ChatMessage[] { new(ChatRole.Assistant, reply) };
        var cut = new SentinelContext(new AgentId("a"), new AgentId("b"), SessionId.New(), messages, new List<AuditEntry>())
        { MaxScanBytes = 30 };
        var detector = Create(name);

        Assert.True(cut.ExceedsScanBudget);
        Assert.True((await detector.AnalyzeAsync(cut, TestContext.Current.CancellationToken)).IsClean);
        Assert.True((await detector.AnalyzeAsync(Ctx(messages, newFrom: 0), TestContext.Current.CancellationToken)).IsClean);
    }

    // Inside the budget the checks still run.
    [Theory]
    [InlineData(nameof(TruncatedOutputDetector))]
    [InlineData(nameof(IncompleteCodeBlockDetector))]
    public async Task FenceChecks_StillRunInsideTheScanBudget(string name)
    {
        var messages = new ChatMessage[] { new(ChatRole.Assistant, "```python\nx = 1") };
        var ctx = new SentinelContext(new AgentId("a"), new AgentId("b"), SessionId.New(), messages, new List<AuditEntry>())
        { MaxScanBytes = 1000 };

        Assert.False((await Create(name).AnalyzeAsync(ctx, TestContext.Current.CancellationToken)).IsClean);
    }

    [Theory]
    [InlineData("Loading...")]
    [InlineData("The answer is that we should,")]
    public async Task TruncatedOutput_TailChecks_IgnoreHistory(string tail)
    {
        var detector = new TruncatedOutputDetector();
        var inHistory = new ChatMessage[] { new(ChatRole.Assistant, tail), new(ChatRole.User, "go on") };
        var asNew = new ChatMessage[] { new(ChatRole.User, "go on"), new(ChatRole.Assistant, tail) };

        Assert.True((await detector.AnalyzeAsync(Ctx(inHistory, newFrom: 1), TestContext.Current.CancellationToken)).IsClean);
        Assert.False((await detector.AnalyzeAsync(Ctx(asNew, newFrom: 1), TestContext.Current.CancellationToken)).IsClean);
    }

    // NewMessageProse is index-aligned with Messages from NewMessagesFrom; TruncatedOutput and WrongLanguage rely on it.
    [Fact]
    public void NewMessageProse_IsIndexAlignedWithTheNewMessages()
    {
        var messages = new ChatMessage[]
        {
            new(ChatRole.User, "zero"), new(ChatRole.Assistant, "one"), new(ChatRole.User, "two"), new(ChatRole.Assistant, "three"),
        };

        var prose = Ctx(messages, newFrom: 2).NewMessageProse;

        Assert.Equal(["two", "three"], prose);
    }
}
