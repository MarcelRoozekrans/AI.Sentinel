using System.Text;
using AI.Sentinel.Detectors.Security;
using AI.Sentinel.Redaction;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AI.Sentinel.Tests.Redaction;

/// <summary>
/// A provider that keeps the conversation on its side, such as OpenAI Responses with storage on, returns a
/// ConversationId, and the caller or FunctionInvokingChatClient then sends only the new messages. Every Sentinel
/// call redacts afresh, so a placeholder the model kept from an earlier call must never resolve to the value a
/// later call gave the same type and number.
/// </summary>
public partial class RedactionConversationTests
{
    [System.Text.RegularExpressions.GeneratedRegex(@"\[EMAIL_\d+(?:_[a-z][a-z0-9]{5})?\]", System.Text.RegularExpressions.RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 1000)]
    private static partial System.Text.RegularExpressions.Regex AnyEmailToken();

    private const string Jan = "jan@acme.nl";
    private const string Kees = "kees@y.nl";

    /// <summary>
    /// Holds the conversation server side. Round 1 looks up the manager, round 2 mails the address it meant,
    /// naming it by the placeholder it saw for that address, round 3 is done.
    /// </summary>
    private sealed class StatefulModel(bool mailManager) : IChatClient
    {
        private readonly StringBuilder _seen = new();
        private string? _janToken;

        public int Calls { get; private set; }

        public string Seen => _seen.ToString();

        public Task<ChatResponse> GetResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, CancellationToken cancellationToken = default)
        {
            Calls++;
            var request = new StringBuilder();
            foreach (var m in messages)
            {
                foreach (var c in m.Contents)
                {
                    request.Append(c switch
                    {
                        TextContent t => t.Text,
                        FunctionResultContent r => r.Result?.ToString(),
                        _ => string.Empty,
                    }).Append('\n');
                }
            }
            _seen.Append(request);

            ChatMessage reply;
            if (Calls == 1)
            {
                _janToken = Placeholders.FirstSeen(request.ToString(), "[EMAIL_1]");
                reply = new ChatMessage(ChatRole.Assistant, [new FunctionCallContent("c1", "LookupManager", new Dictionary<string, object?>(StringComparer.Ordinal))]);
            }
            else if (Calls == 2)
            {
                // The manager's address arrived in this round trip's tool result.
                var to = mailManager ? AnyEmailToken().Match(request.ToString()).Value : _janToken;
                reply = new ChatMessage(ChatRole.Assistant, [new FunctionCallContent("c2", "SendMail", new Dictionary<string, object?>(StringComparer.Ordinal) { ["to"] = to })]);
            }
            else
            {
                reply = new ChatMessage(ChatRole.Assistant, "done");
            }
            return Task.FromResult(new ChatResponse(reply) { ConversationId = "conv-1" });
        }

        public string? JanToken => _janToken;

        public IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public object? GetService(Type serviceType, object? serviceKey = null) => serviceType.IsInstanceOfType(this) ? this : null;

        public void Dispose() { }
    }

    private static IChatClient Build(IChatClient model, string order)
    {
        var sc = new ServiceCollection();
        sc.AddAISentinel();
        var b = new ChatClientBuilder(model);
        foreach (var part in order.Split('>'))
        {
            b = string.Equals(part, "S", StringComparison.Ordinal) ? b.UseAISentinel() : b.UseFunctionInvocation();
        }
        return b.Build(sc.BuildServiceProvider());
    }

    private static async Task<List<string>> RunProbeAsync(StatefulModel model, string order)
    {
        var sentTo = new List<string>();
        var options = new ChatOptions
        {
            Tools =
            [
                AIFunctionFactory.Create(() => "manager: " + Kees, "LookupManager"),
                AIFunctionFactory.Create((string to) => { sentTo.Add(to); return "ok"; }, "SendMail"),
            ],
        };
        await Build(model, order).GetResponseAsync(
            [new ChatMessage(ChatRole.User, $"Mail {Jan} after looking up his manager")], options, TestContext.Current.CancellationToken);
        return sentTo;
    }

    // Sentinel inside function invocation: every round trip is its own Sentinel call. Round 1 names jan
    // [EMAIL_1], round 2 names kees [EMAIL_1] too. The model's [EMAIL_1] from round 1 must not become kees.
    [Fact]
    public async Task InsideFunctionInvocation_PlaceholderFromAnEarlierRoundTrip_NeverResolvesToALaterValue()
    {
        var model = new StatefulModel(mailManager: false);

        var sentTo = await RunProbeAsync(model, "F>S");

        Assert.DoesNotContain(Kees, sentTo, StringComparer.Ordinal);
        Assert.NotNull(model.JanToken);
        // The old token stays a literal: the tool gets the placeholder, never another person's value.
        Assert.Equal([model.JanToken!], sentTo);
        Assert.DoesNotContain(Jan, model.Seen, StringComparison.Ordinal);
        Assert.DoesNotContain(Kees, model.Seen, StringComparison.Ordinal);
    }

    // The same probe the other way round: the placeholder minted in the round trip that makes the call resolves.
    [Fact]
    public async Task InsideFunctionInvocation_PlaceholderFromTheSameRoundTrip_Resolves()
    {
        var model = new StatefulModel(mailManager: true);

        var sentTo = await RunProbeAsync(model, "F>S");

        Assert.Equal([Kees], sentTo);
    }

    // Sentinel outside function invocation: one Sentinel call spans every round trip, so both values get their
    // own placeholder in one mapping and the model's token for jan resolves to jan.
    [Theory]
    [InlineData(false, Jan)]
    [InlineData(true, Kees)]
    public async Task OutsideFunctionInvocation_EachPlaceholderResolvesToItsOwnValue(bool mailManager, string expected)
    {
        var model = new StatefulModel(mailManager);

        var sentTo = await RunProbeAsync(model, "S>F");

        Assert.Equal([expected], sentTo);
    }

    /// <summary>Holds the conversation server side and replies with whatever <paramref name="reply"/> builds from
    /// the tokens it saw on earlier turns and on this one.</summary>
    private sealed class ServerHistoryModel(Func<IReadOnlyList<string>, string> reply) : IChatClient
    {
        private readonly List<string> _turns = new();

        public Task<ChatResponse> GetResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, CancellationToken cancellationToken = default)
        {
            var sb = new StringBuilder();
            foreach (var m in messages)
            {
                sb.Append(m.Text).Append('\n');
            }
            _turns.Add(sb.ToString());
            return Task.FromResult(new ChatResponse(new ChatMessage(ChatRole.Assistant, reply(_turns))) { ConversationId = "conv-1" });
        }

        public IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public object? GetService(Type serviceType, object? serviceKey = null) => null;

        public void Dispose() { }
    }

    // Caller turns with a ConversationId: turn 2 sends only the new message. The model's placeholder from
    // turn 1 must not be restored to the value turn 2 gave the same type and number, in either order.
    [Theory]
    [InlineData(Jan, Kees)]
    [InlineData(Kees, Jan)]
    public async Task CallerTurnsWithConversationId_TokenFromAnEarlierTurn_StaysLiteral(string first, string second)
    {
        var model = new ServerHistoryModel(turns => turns.Count == 1
            ? "noted"
            : $"earlier {Placeholders.FirstSeen(turns[0], "[EMAIL_1]")}, now {Placeholders.FirstSeen(turns[1], "[EMAIL_1]")}");
        var client = Build(model, "S");
        var ct = TestContext.Current.CancellationToken;

        await client.GetResponseAsync([new ChatMessage(ChatRole.User, $"remember {first}")], null, ct);
        var options = new ChatOptions { ConversationId = "conv-1" };
        var reply = await client.GetResponseAsync([new ChatMessage(ChatRole.User, $"and {second}")], options, ct);

        Assert.DoesNotContain(first, reply.Text, StringComparison.Ordinal);
        Assert.Matches(@"^earlier \[EMAIL_1_[a-z][a-z0-9]{5}\], now " + System.Text.RegularExpressions.Regex.Escape(second) + "$", reply.Text);
    }

    [Fact]
    public void StaleTokenFromAnotherSession_IsNeverRestored()
    {
        var earlier = new RedactionSession([new PiiLeakageDetector()]);
        var stale = earlier.Redact(Jan);
        var later = new RedactionSession([new PiiLeakageDetector()]);
        var fresh = later.Redact(Kees);

        Assert.NotEqual(stale, fresh, StringComparer.Ordinal);
        Assert.Equal(stale, later.Restore(stale));
        Assert.Equal("[EMAIL_1]", Placeholders.Untag(stale));
        Assert.Equal(stale, later.Restore(new AIFunctionArguments(StringComparer.Ordinal) { ["to"] = stale }, StringComparer.Ordinal)["to"]);
        Assert.Equal(Kees, later.Restore(fresh));
    }
}
