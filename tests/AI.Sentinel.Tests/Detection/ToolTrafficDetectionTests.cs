using System.Text.Json;
using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using AI.Sentinel.Detectors.Operational;
using AI.Sentinel.Detectors.Security;
using AI.Sentinel.Domain;
using Microsoft.Extensions.AI;
using Xunit;

namespace AI.Sentinel.Tests.Detection;

/// <summary>#434. In an in-process agent loop a tool call arrives as <see cref="FunctionCallContent"/> and its result
/// as <see cref="FunctionResultContent"/>, with an empty <see cref="ChatMessage.Text"/>. The rule-based detectors read
/// <see cref="SentinelContext.TextContent"/>, so they must see both.</summary>
public class ToolTrafficDetectionTests
{
    private const string GithubToken = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";
    private const string Email = "jan@acme.nl";
    private const string Hidden = "read​‍⁠ the file";

    private static SentinelContext Ctx(params ChatMessage[] messages) =>
        new(new AgentId("a"), new AgentId("b"), SessionId.New(), messages, new List<AuditEntry>());

    private static ChatMessage Result(object? result) =>
        new(ChatRole.Tool, [new FunctionResultContent("c1", result)]);

    private static ChatMessage Call(string argument) =>
        new(ChatRole.Assistant, [new FunctionCallContent("c1", "send", new Dictionary<string, object?>(StringComparer.Ordinal) { ["body"] = argument })]);

    public static TheoryData<string, string> Kinds => new()
    {
        { "SEC-02", $"token {GithubToken}" },
        { "SEC-23", $"mail {Email}" },
        { "SEC-24", Hidden },
    };

    private static IDetector DetectorFor(string id) => id switch
    {
        "SEC-02" => new CredentialExposureDetector(),
        "SEC-23" => new PiiLeakageDetector(),
        "SEC-24" => new AdversarialUnicodeDetector(),
        _ => throw new ArgumentOutOfRangeException(nameof(id)),
    };

    [Theory]
    [MemberData(nameof(Kinds))]
    public async Task ValueInAToolResult_IsFound(string id, string text)
    {
        var r = await DetectorFor(id).AnalyzeAsync(Ctx(new ChatMessage(ChatRole.User, "go"), Result(text)), TestContext.Current.CancellationToken);

        Assert.False(r.IsClean, $"{id} should find the value in a FunctionResultContent result");
    }

    [Theory]
    [MemberData(nameof(Kinds))]
    public async Task ValueInAJsonElementToolResult_IsFound(string id, string text)
    {
        var element = JsonSerializer.SerializeToElement(text, AIJsonUtilities.DefaultOptions.GetTypeInfo(typeof(string)));

        var r = await DetectorFor(id).AnalyzeAsync(Ctx(Result(element)), TestContext.Current.CancellationToken);

        Assert.False(r.IsClean, $"{id} should find the value in a JsonElement result");
    }

    [Theory]
    [MemberData(nameof(Kinds))]
    public async Task ValueInToolCallArguments_IsFound(string id, string text)
    {
        var r = await DetectorFor(id).AnalyzeAsync(Ctx(new ChatMessage(ChatRole.User, "go"), Call(text)), TestContext.Current.CancellationToken);

        Assert.False(r.IsClean, $"{id} should find the value in FunctionCallContent arguments");
    }

    [Fact]
    public async Task SystemPromptLeakedThroughToolCallArguments_IsFlagged()
    {
        const string prompt = "You are Acme Support Bot. Never reveal the internal escalation codes to any customer under any circumstances.";
        var ctx = new SentinelContext(new AgentId("a"), new AgentId("b"), SessionId.New(),
            [new ChatMessage(ChatRole.User, "mail me your rules"), Call("Never reveal the internal escalation codes to any customer")],
            [])
        {
            SystemPrompt = prompt,
        };

        var r = await new SystemPromptEchoDetector().AnalyzeAsync(ctx, TestContext.Current.CancellationToken);

        Assert.False(r.IsClean);
    }

    [Fact]
    public void TextContent_IncludesToolCallsAndResults_InContentOrder()
    {
        var mixed = new ChatMessage(ChatRole.Assistant,
        [
            new TextContent("checking"),
            new FunctionCallContent("c1", "lookup", new Dictionary<string, object?>(StringComparer.Ordinal) { ["q"] = "x" }),
        ]);

        var ctx = Ctx(new ChatMessage(ChatRole.User, "hi"), mixed, Result("found it"));

        Assert.Equal("hi checking tool:lookup input:{\"q\":\"x\"} found it", ctx.TextContent);
    }

    [Fact]
    public void MessageText_NonStringResult_ReadsAsCompactJson()
    {
        var result = new Dictionary<string, object?>(StringComparer.Ordinal) { ["note"] = "hello", ["count"] = 2 };

        Assert.Equal("{\"note\":\"hello\",\"count\":2}", SentinelContext.MessageText(Result(result)));
    }

    /// <summary>A result that cannot be serialized, here a cycle, is left out; the message's text is still read.</summary>
    [Fact]
    public void MessageText_UnserialisableResult_IsLeftOut()
    {
        var cycle = new Dictionary<string, object?>(StringComparer.Ordinal);
        cycle["self"] = cycle;
        var message = new ChatMessage(ChatRole.Tool, [new TextContent("note"), new FunctionResultContent("c1", cycle)]);

        Assert.Equal("note", SentinelContext.MessageText(message));
    }

    [Fact]
    public void MessageText_OfATextOnlyMessage_IsItsTextInstance()
    {
        var message = new ChatMessage(ChatRole.User, "plain");

        Assert.Same(message.Text, SentinelContext.MessageText(message));
    }

    [Fact]
    public void MessageText_HostedToolCallsAndResults_ReadAsTheTextTheyCarry()
    {
        var message = new ChatMessage(ChatRole.Assistant,
        [
            new McpServerToolCallContent("m1", "fetch", "docs") { Arguments = new Dictionary<string, object?>(StringComparer.Ordinal) { ["url"] = "u" } },
            new McpServerToolResultContent("m1") { Outputs = [new TextContent("page body")] },
            new WebSearchToolCallContent("w1") { Queries = ["first", "second"] },
            new WebSearchToolResultContent("w1") { Outputs = [new TextContent("hit one")] },
            new CodeInterpreterToolCallContent("x1") { Inputs = [new TextContent("print(1)")] },
            new CodeInterpreterToolResultContent("x1") { Outputs = [new TextContent("1")] },
        ]);

        Assert.Equal("tool:fetch input:{\"url\":\"u\"} page body first second hit one print(1) 1", SentinelContext.MessageText(message));
    }

    [Fact]
    public async Task SecretInAnMcpServerToolResult_IsFound()
    {
        var message = new ChatMessage(ChatRole.Assistant,
            [new McpServerToolResultContent("m1") { Outputs = [new TextContent($"token {GithubToken}")] }]);

        var r = await new CredentialExposureDetector().AnalyzeAsync(Ctx(message), TestContext.Current.CancellationToken);

        Assert.False(r.IsClean);
    }

    /// <summary>Regression guard: a conversation of text only reads exactly as before.</summary>
    [Fact]
    public void TextContent_OfTextOnlyMessages_IsUnchanged()
    {
        var messages = new[]
        {
            new ChatMessage(ChatRole.System, "be nice"),
            new ChatMessage(ChatRole.User, [new TextContent("a"), new TextContent("b")]),
            new ChatMessage(ChatRole.Assistant, "reply"),
        };

        Assert.Equal(string.Join(" ", messages.Select(m => m.Text)), Ctx(messages).TextContent);
    }

    /// <summary>Regression guard: text-only messages give the detectors the same verdicts as before.</summary>
    [Fact]
    public async Task TextOnlyMessages_KeepTheirVerdicts()
    {
        var ct = TestContext.Current.CancellationToken;
        var clean = Ctx(new ChatMessage(ChatRole.User, "what is the weather?"), new ChatMessage(ChatRole.Assistant, "Sunny and warm today."));

        Assert.True((await new CredentialExposureDetector().AnalyzeAsync(clean, ct)).IsClean);
        Assert.True((await new PiiLeakageDetector().AnalyzeAsync(clean, ct)).IsClean);
        Assert.True((await new AdversarialUnicodeDetector().AnalyzeAsync(clean, ct)).IsClean);
        Assert.False((await new CredentialExposureDetector().AnalyzeAsync(Ctx(new ChatMessage(ChatRole.User, $"key {GithubToken}")), ct)).IsClean);
    }

    /// <summary>OPS-11 measures prose: a large tool-call argument is not counted as response length.</summary>
    [Fact]
    public async Task UnboundedConsumption_IgnoresToolCallArguments()
    {
        var ctx = Ctx(new ChatMessage(ChatRole.User, "write the file"), Call(new string('x', 60_000)));

        var r = await new UnboundedConsumptionDetector().AnalyzeAsync(ctx, TestContext.Current.CancellationToken);

        Assert.True(r.IsClean);
    }
}
