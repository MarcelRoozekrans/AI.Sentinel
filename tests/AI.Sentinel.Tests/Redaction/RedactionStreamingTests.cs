using System.Runtime.CompilerServices;
using System.Text.RegularExpressions;
using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using AI.Sentinel.Detectors.Security;
using AI.Sentinel.Domain;
using AI.Sentinel.Intervention;
using AI.Sentinel.Tests.Helpers;
using Microsoft.Extensions.AI;
using Xunit;
using static AI.Sentinel.Tests.Redaction.RedactionPipelineTests;

namespace AI.Sentinel.Tests.Redaction;

public class RedactionStreamingTests
{
    private const string Email = "jan@acme.nl";
    private const string ApiKey = "abc123def456ghi789";

    public static TheoryData<bool> IdModes => new() { true, false };

    public static TheoryData<string, bool> BuilderOrders => new()
    {
        { "S>F", true }, { "F>S", true }, { "S>F", false }, { "F>S", false },
    };

    private static RecordingModel WithIds(RecordingModel model, bool messageIds)
    {
        model.StreamMessageIds = messageIds;
        return model;
    }

    private static async Task<List<ChatResponseUpdate>> StreamAsync(Harness h, string prompt, ChatOptions? options = null)
    {
        var updates = new List<ChatResponseUpdate>();
        await foreach (var u in h.Client.GetStreamingResponseAsync(
            [new ChatMessage(ChatRole.User, prompt)], options, TestContext.Current.CancellationToken))
        {
            updates.Add(u);
        }
        return updates;
    }

    private static (SentinelPipeline Sentinel, RingBufferAuditStore Audit) Direct(IChatClient model, IDetector? detector = null, SentinelOptions? options = null)
    {
        var audit = new RingBufferAuditStore();
        options ??= new SentinelOptions();
        var pipeline = new DetectionPipeline([detector ?? new PiiLeakageDetector()], configurations: null, escalationClient: null);
        return (new SentinelPipeline(model, pipeline, audit, new InterventionEngine(options, mediator: null), options), audit);
    }

    private static string TextOf(IReadOnlyList<ChatResponseUpdate> updates)
    {
        var parts = new string[updates.Count];
        for (var i = 0; i < updates.Count; i++)
        {
            parts[i] = updates[i].Text;
        }
        return string.Concat(parts);
    }

    private static List<FunctionCallContent> CallsOf(IReadOnlyList<ChatResponseUpdate> updates)
    {
        var calls = new List<FunctionCallContent>();
        foreach (var u in updates)
        {
            foreach (var c in u.Contents)
            {
                if (c is FunctionCallContent call)
                {
                    calls.Add(call);
                }
            }
        }
        return calls;
    }

    // --- The brief's three ---

    [Fact]
    public async Task Streaming_PlaceholderSplitAcrossUpdates_Restored()
    {
        var model = new FixedStream(
            new ChatResponseUpdate(ChatRole.Assistant, "mail [EMA"),
            new ChatResponseUpdate(ChatRole.Assistant, "IL_1] today"));
        var (sentinel, _) = Direct(model);

        var result = await sentinel.GetStreamingResultAsync([new ChatMessage(ChatRole.User, $"Mail {Email}")], null, TestContext.Current.CancellationToken);

        Assert.True(result.IsSuccess);
        Assert.Equal(2, result.Value.Count);
        Assert.Equal($"mail {Email} today", TextOf(result.Value));
        foreach (var u in result.Value)
        {
            // No update carries part of a placeholder.
            Assert.DoesNotContain("[EMA", u.Text, StringComparison.Ordinal);
            Assert.DoesNotContain("IL_1", u.Text, StringComparison.Ordinal);
        }
        Assert.Contains("[EMAIL_1]", Placeholders.Untag(model.Seen), StringComparison.Ordinal);
        Assert.DoesNotContain(Email, model.Seen, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Streaming_UnterminatedBracketAtEnd_StaysInTheLastUpdate()
    {
        var model = new FixedStream(
            new ChatResponseUpdate(ChatRole.Assistant, "x [EMAIL"),
            new ChatResponseUpdate(ChatRole.Assistant, "_1] and [EM"));
        var (sentinel, _) = Direct(model);

        var result = await sentinel.GetStreamingResultAsync([new ChatMessage(ChatRole.User, $"Mail {Email}")], null, TestContext.Current.CancellationToken);

        Assert.True(result.IsSuccess);
        Assert.Equal(2, result.Value.Count);
        Assert.Equal("x ", result.Value[0].Text);
        Assert.Equal($"{Email} and [EM", result.Value[1].Text);
    }

    [Fact]
    public async Task Streaming_HeldTextNeverMovesIntoAnotherMessage()
    {
        var model = new FixedStream(
            new ChatResponseUpdate(ChatRole.Assistant, "first [EM") { MessageId = "m1" },
            new ChatResponseUpdate(ChatRole.Assistant, "AIL_1] second") { MessageId = "m2" });
        var (sentinel, _) = Direct(model);

        var result = await sentinel.GetStreamingResultAsync([new ChatMessage(ChatRole.User, $"Mail {Email}")], null, TestContext.Current.CancellationToken);

        Assert.True(result.IsSuccess);
        Assert.Equal("first [EM", result.Value[0].Text);
        Assert.Equal($"AIL_1_{model.Tag}] second", result.Value[1].Text);
    }

    private static async Task<IReadOnlyList<ChatResponseUpdate>> RestoreAsync(params ChatResponseUpdate[] updates)
    {
        var (sentinel, _) = Direct(new FixedStream(updates));
        var result = await sentinel.GetStreamingResultAsync([new ChatMessage(ChatRole.User, $"Mail {Email}")], null, TestContext.Current.CancellationToken);
        Assert.True(result.IsSuccess);
        Assert.Equal(updates.Length, result.Value.Count);
        return result.Value;
    }

    // ToChatResponse, which the response scan uses, continues the current message when an update has no id.
    [Fact]
    public async Task Streaming_MessageIdOnFirstChunkOnly_PlaceholderStillRestored()
    {
        var updates = await RestoreAsync(
            new ChatResponseUpdate(ChatRole.Assistant, "mail [EMA") { MessageId = "m1" },
            new ChatResponseUpdate(null, "IL_1] today"));

        Assert.Equal("mail ", updates[0].Text);
        Assert.Equal($"{Email} today", updates[1].Text);
    }

    // A role change starts a new message even without ids, so held text never crosses a tool update.
    [Fact]
    public async Task Streaming_RoleChangeWithoutIds_HeldTextReleasedInItsOwnMessage()
    {
        var updates = await RestoreAsync(
            new ChatResponseUpdate(ChatRole.Assistant, "a [EM"),
            new ChatResponseUpdate(ChatRole.Tool, [new FunctionResultContent("c1", "r")]),
            new ChatResponseUpdate(ChatRole.Assistant, "AIL_1] b"));

        Assert.Equal("a [EM", updates[0].Text);
        Assert.Matches(@"^AIL_1_[a-z][a-z0-9]{5}\] b$", updates[2].Text);
    }

    [Fact]
    public async Task Streaming_HeldTailGrowsOverUpdates_ReleasedAtMessageBoundary()
    {
        var updates = await RestoreAsync(
            new ChatResponseUpdate(ChatRole.Assistant, "x [EM") { MessageId = "m1" },
            new ChatResponseUpdate(ChatRole.Assistant, "AI") { MessageId = "m1" },
            new ChatResponseUpdate(ChatRole.Assistant, "L_") { MessageId = "m1" },
            new ChatResponseUpdate(ChatRole.Assistant, "y") { MessageId = "m2" });

        // Released once, as it was, into the last text of the message it belongs to.
        Assert.Equal("x ", updates[0].Text);
        Assert.Equal("", updates[1].Text);
        Assert.Equal("[EMAIL_", updates[2].Text);
        Assert.Equal("y", updates[3].Text);
        Assert.Equal("x [EMAIL_y", TextOf(updates));
    }

    [Fact]
    public async Task Streaming_TwoTextContentsInOneUpdate_CarryMovesWithinTheUpdate()
    {
        var updates = await RestoreAsync(
            new ChatResponseUpdate(ChatRole.Assistant, [new TextContent("a [EMA"), new TextContent("IL_1] b")]));

        var contents = updates[0].Contents;
        Assert.Equal(2, contents.Count);
        Assert.Equal("a ", Assert.IsType<TextContent>(contents[0]).Text);
        Assert.Equal($"{Email} b", Assert.IsType<TextContent>(contents[1]).Text);
    }

    [Fact]
    public async Task Streaming_ReasoningSplitAcrossUpdates_Restored()
    {
        var model = new FixedStream(
            new ChatResponseUpdate(ChatRole.Assistant, [new TextReasoningContent("think [EM")]),
            new ChatResponseUpdate(ChatRole.Assistant, [new TextReasoningContent("AIL_1]")]),
            new ChatResponseUpdate(ChatRole.Assistant, "done."));
        var (sentinel, _) = Direct(model);

        var result = await sentinel.GetStreamingResultAsync([new ChatMessage(ChatRole.User, $"Mail {Email}")], null, TestContext.Current.CancellationToken);

        Assert.True(result.IsSuccess);
        Assert.Equal("think ", Assert.IsType<TextReasoningContent>(Assert.Single(result.Value[0].Contents)).Text);
        Assert.Equal(Email, Assert.IsType<TextReasoningContent>(Assert.Single(result.Value[1].Contents)).Text);
    }

    [Fact]
    public async Task Streaming_FunctionCallUpdate_ArgumentsRestored()
    {
        var model = new FixedStream(
            new ChatResponseUpdate(ChatRole.Assistant, "Sending"),
            new ChatResponseUpdate(ChatRole.Assistant, [
                new FunctionCallContent("c1", "SendMail", new Dictionary<string, object?>(StringComparer.Ordinal) { ["to"] = "[EMAIL_1]" }),
            ]));
        var (sentinel, _) = Direct(model);

        var result = await sentinel.GetStreamingResultAsync([new ChatMessage(ChatRole.User, $"Mail {Email}")], null, TestContext.Current.CancellationToken);

        Assert.True(result.IsSuccess);
        var call = Assert.Single(CallsOf(result.Value));
        Assert.Equal(Email, call.Arguments!["to"]?.ToString());
        Assert.Equal("c1", call.CallId);
        Assert.Equal("SendMail", call.Name);
    }

    [Fact]
    public async Task Streaming_UpdateCountAndNonTextContentPreserved()
    {
        var created = new DateTimeOffset(2026, 10, 15, 12, 0, 0, TimeSpan.Zero);
        var usage = new UsageContent(new UsageDetails { InputTokenCount = 3 });
        var image = new DataContent(new byte[] { 1, 2, 3 }, "image/png");
        var props = new AdditionalPropertiesDictionary { ["k"] = "v" };
        var raw = new object();
        ChatResponseUpdate Meta(ChatResponseUpdate u)
        {
            u.MessageId = "m1";
            u.ResponseId = "r1";
            u.ConversationId = "conv1";
            u.ModelId = "model-x";
            u.CreatedAt = created;
            u.AuthorName = "bot";
            u.AdditionalProperties = props;
            u.RawRepresentation = raw;
            return u;
        }
        var model = new FixedStream(
            Meta(new ChatResponseUpdate(ChatRole.Assistant, "Hi [EMA")),
            Meta(new ChatResponseUpdate(ChatRole.Assistant, [image])),
            Meta(new ChatResponseUpdate(ChatRole.Assistant, "IL_1]!")),
            Meta(new ChatResponseUpdate(ChatRole.Assistant, [usage]) { FinishReason = ChatFinishReason.Stop }));
        var (sentinel, _) = Direct(model);

        var result = await sentinel.GetStreamingResultAsync([new ChatMessage(ChatRole.User, $"Mail {Email}")], null, TestContext.Current.CancellationToken);

        Assert.True(result.IsSuccess);
        var updates = result.Value;
        Assert.Equal(4, updates.Count);
        Assert.Equal($"Hi {Email}!", TextOf(updates));
        Assert.Same(image, Assert.Single(updates[1].Contents));
        Assert.Same(usage, Assert.Single(updates[3].Contents));
        Assert.Equal(ChatFinishReason.Stop, updates[3].FinishReason);
        foreach (var u in updates)
        {
            Assert.Equal(ChatRole.Assistant, u.Role);
            Assert.Equal("m1", u.MessageId);
            Assert.Equal("r1", u.ResponseId);
            Assert.Equal("conv1", u.ConversationId);
            Assert.Equal("model-x", u.ModelId);
            Assert.Equal(created, u.CreatedAt);
            Assert.Equal("bot", u.AuthorName);
            Assert.Same(props, u.AdditionalProperties);
            Assert.Same(raw, u.RawRepresentation);
        }
        // The inner client's updates are not mutated: they still hold the placeholder.
        Assert.Equal("Hi [EMA", model.Updates[0].Text);
    }

    // --- Mirrors of the non-streaming pipeline tests ---

    [Theory]
    [MemberData(nameof(IdModes))]
    public async Task Streaming_ModelSeesPlaceholder_UserSeesRealValue(bool messageIds)
    {
        var h = Build("S", WithIds(RecordingModel.Echo(), messageIds));

        var updates = await StreamAsync(h, $"Mail {Email} please");

        Assert.Contains("[EMAIL_1]", h.Model.AllSeen, StringComparison.Ordinal);
        Assert.DoesNotContain(Email, h.Model.AllSeen, StringComparison.Ordinal);
        Assert.True(updates.Count > 3);
        Assert.Equal($"Echo: Mail {Email} please", TextOf(updates));
    }

    [Theory]
    [MemberData(nameof(IdModes))]
    public async Task Streaming_RestoreDisabled_ReplyKeepsPlaceholders(bool messageIds)
    {
        var h = Build("S", WithIds(RecordingModel.Echo(), messageIds), o => o.RestoreRedactedValues = false);

        var updates = await StreamAsync(h, $"Mail {Email} please");

        Assert.Equal("Echo: Mail [EMAIL_1] please", Placeholders.Untag(TextOf(updates)));
    }

    [Theory]
    [MemberData(nameof(BuilderOrders))]
    public async Task Streaming_ToolGetsRealValue_ModelNeverSeesIt(string order, bool messageIds)
    {
        var h = Build(order, WithIds(RecordingModel.CallsTool("SendMail", "to", "[EMAIL_1]", "Mailed [EMAIL_1]"), messageIds));
        var seen = new List<string>();
        var options = new ChatOptions { Tools = [AIFunctionFactory.Create((string to) => { seen.Add(to); return "sent to " + to; }, "SendMail")] };

        var updates = await StreamAsync(h, $"Mail {Email} please", options);

        Assert.Equal([Email], seen);
        Assert.Equal(2, h.Model.Calls);
        Assert.DoesNotContain(Email, h.Model.AllSeen, StringComparison.Ordinal);
        Assert.Contains("sent to [EMAIL_1]", h.Model.AllSeen, StringComparison.Ordinal);
        Assert.Equal($"Mailed {Email}", TextOf(updates));
    }

    [Theory]
    [MemberData(nameof(BuilderOrders))]
    public async Task Streaming_ApiKeyPlaceholder_NeverRestoredIntoToolArguments(string order, bool messageIds)
    {
        var h = Build(order, WithIds(RecordingModel.CallsTool("Lookup", "key", "[API_KEY_1]", "Your key is [API_KEY_1]"), messageIds));
        var seen = new List<string>();
        var options = new ChatOptions { Tools = [AIFunctionFactory.Create((string key) => { seen.Add(key); return "ok"; }, "Lookup")] };

        var updates = await StreamAsync(h, $"my api_key={ApiKey}", options);

        Assert.Equal("[API_KEY_1]", Placeholders.Untag(Assert.Single(seen)));
        Assert.DoesNotContain(ApiKey, h.Model.AllSeen, StringComparison.Ordinal);
        var call = Assert.Single(CallsOf(updates));
        // The model names the key by the token of the round trip it replies in, so the reply is restored.
        Assert.Equal($"Your key is {ApiKey}", TextOf(updates));
        if (string.Equals(order, "S>F", StringComparison.Ordinal))
        {
            // The call is answered by the result streamed after it, so it is history and holds the real key.
            Assert.Equal(ApiKey, call.Arguments!["key"]?.ToString());
        }
        else
        {
            // The ruled inside-order residue, as for the non-streaming path: the call left Sentinel unanswered and
            // kept its placeholder, whose tag no later round trip knows.
            Assert.Equal("[API_KEY_1]", Placeholders.Untag(call.Arguments!["key"]?.ToString()));
        }
    }

    [Theory]
    [MemberData(nameof(IdModes))]
    public async Task Streaming_UnansweredSecretCall_KeepsPlaceholder_PiiArgumentRestored(bool messageIds)
    {
        var h = Build("S", WithIds(new RecordingModel(_ => new ChatMessage(ChatRole.Assistant, [
            new TextContent("Calling with [API_KEY_1] for [EMAIL_1]"),
            new FunctionCallContent("c1", "Lookup", new Dictionary<string, object?>(StringComparer.Ordinal) { ["key"] = "[API_KEY_1]", ["to"] = "[EMAIL_1]" }),
        ])), messageIds));

        var updates = await StreamAsync(h, $"api_key={ApiKey} for {Email}");

        Assert.Equal($"Calling with {ApiKey} for {Email}", TextOf(updates));
        var call = Assert.Single(CallsOf(updates));
        Assert.Equal("[API_KEY_1]", Placeholders.Untag(call.Arguments!["key"]?.ToString()));
        Assert.Equal(Email, call.Arguments["to"]?.ToString());
    }

    [Theory]
    [MemberData(nameof(IdModes))]
    public async Task Streaming_RedactionAudited_ResponseScannedBeforeRestore_Notified(bool messageIds)
    {
        var h = Build("S", WithIds(RecordingModel.Echo(), messageIds));

        await StreamAsync(h, $"Mail {Email} please.");

        // Only the redaction entry: the echoed reply was scanned with its placeholder, before the restore.
        var entry = Assert.Single(await RecordingAuditForwarder.ReadAllAsync(h.Audit));
        Assert.Equal("REDACTED", entry.PolicyCode);
        Assert.Equal(Severity.None, entry.Severity);
        Assert.Equal("Redacted 1 EMAIL", entry.Summary);
        var applied = Assert.IsType<InterventionAppliedNotification>(Assert.Single(h.Published));
        Assert.Equal(SentinelAction.Redact, applied.Action);
        Assert.Equal(1, applied.Redactions!["EMAIL"]);
    }

    private sealed class ThrowingRedactor : IRedactingDetector
    {
        public DetectorId Id { get; } = new("TST-RD");
        public DetectorCategory Category => DetectorCategory.Security;
        public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct) =>
            ValueTask.FromResult(DetectionResult.Clean(Id));
        public IReadOnlyList<RedactionSpan> FindSpans(string text) =>
            throw new RegexMatchTimeoutException(text, "pattern", TimeSpan.FromSeconds(1));
    }

    [Fact]
    public async Task Streaming_RedactionThrows_FailsClosed_NothingSent()
    {
        var model = new FixedStream(new ChatResponseUpdate(ChatRole.Assistant, "ok"));
        var (sentinel, _) = Direct(model, new ThrowingRedactor());

        var result = await sentinel.GetStreamingResultAsync([new ChatMessage(ChatRole.User, $"Mail {Email}")], null, TestContext.Current.CancellationToken);

        var failure = Assert.IsType<SentinelError.PipelineFailure>(result.Error);
        Assert.DoesNotContain(Email, failure.Message, StringComparison.Ordinal);
        Assert.Null(failure.Inner);
        Assert.Equal(0, model.Calls);
    }

    [Theory]
    [MemberData(nameof(IdModes))]
    public async Task Streaming_ToolArgumentsCannotBeRestored_FailsClosed_ToolNeverRuns(bool messageIds)
    {
        var payload = new Dictionary<string, object?>(StringComparer.Ordinal) { ["[EMAIL_1]"] = "a", [Email] = "b" };
        var h = Build("S>F", WithIds(RecordingModel.CallsTool("Send", "payload", payload, "done"), messageIds));
        var ran = 0;
        var options = new ChatOptions { Tools = [AIFunctionFactory.Create((Dictionary<string, object?> payload) => { ran++; return "ok"; }, "Send")] };

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => StreamAsync(h, $"Mail {Email}", options));

        Assert.Equal(0, ran);
        Assert.Equal(1, h.Model.Calls);
        Assert.DoesNotContain(Email, ex.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Streaming_InnerCallCancelled_RedactionIsStillAudited()
    {
        using var cts = new CancellationTokenSource();
        var model = new RecordingModel(_ =>
        {
            cts.Cancel();
            throw new OperationCanceledException(cts.Token);
        });
        var (sentinel, audit) = Direct(model);

        var result = await sentinel.GetStreamingResultAsync([new ChatMessage(ChatRole.User, $"Mail {Email}")], null, cts.Token);

        Assert.True(result.IsFailure);
        var entry = Assert.Single(await RecordingAuditForwarder.ReadAllAsync(audit));
        Assert.Equal("REDACTED", entry.PolicyCode);
        Assert.Equal("Redacted 1 EMAIL", entry.Summary);
    }

    private sealed class FixedStream(params ChatResponseUpdate[] updates) : IChatClient
    {
        private readonly List<string> _seen = new();
        private int _calls;

        public ChatResponseUpdate[] Updates => updates;

        public int Calls => Volatile.Read(ref _calls);

        public string Seen
        {
            get { lock (_seen) { return string.Join("\n", _seen); } }
        }

        public Task<ChatResponse> GetResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        public async IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(
            IEnumerable<ChatMessage> messages,
            ChatOptions? options = null,
            [EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            Interlocked.Increment(ref _calls);
            var request = new List<string>();
            foreach (var m in messages)
            {
                request.Add(m.Text);
            }
            lock (_seen) { _seen.AddRange(request); }
            Tag = Placeholders.TagOf(string.Join("\n", request));
            foreach (var u in updates)
            {
                await Task.Yield();
                yield return Tag is null ? u : WithTag(u, Tag);
            }
        }

        /// <summary>The tag of the placeholders in the last request, which the scripted updates are given.</summary>
        public string? Tag { get; private set; }

        // Scripted placeholders, whole or split across updates, are written untagged: [EMA + IL_1]. The model
        // writes the tag it was sent. A copy, so Updates keeps the script as written.
        private static ChatResponseUpdate WithTag(ChatResponseUpdate update, string tag)
        {
            var contents = new List<AIContent>(update.Contents.Count);
            foreach (var c in update.Contents)
            {
                contents.Add(c switch
                {
                    TextContent t => new TextContent(Placeholders.AddTag(t.Text, tag)),
                    TextReasoningContent r => new TextReasoningContent(Placeholders.AddTag(r.Text, tag)),
                    FunctionCallContent call when call.Arguments is not null => new FunctionCallContent(call.CallId, call.Name, TagArguments(call.Arguments, tag)),
                    _ => c,
                });
            }
            var copy = update.Clone();
            copy.Contents = contents;
            return copy;
        }

        private static Dictionary<string, object?> TagArguments(IDictionary<string, object?> arguments, string tag)
        {
            var result = new Dictionary<string, object?>(StringComparer.Ordinal);
            foreach (var (key, value) in arguments)
            {
                result[key] = value is string text ? Placeholders.AddTag(text, tag) : value;
            }
            return result;
        }

        public object? GetService(Type serviceType, object? serviceKey = null) => null;

        public void Dispose() { }
    }
}
