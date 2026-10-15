using AI.Sentinel.Audit;
using AI.Sentinel.Tests.Helpers;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AI.Sentinel.Tests.Redaction;

/// <summary>ChatOptions.Instructions is sent to the model as a system prompt, so it is redacted like a message.</summary>
public class RedactionInstructionsTests
{
    private const string Email = "jan@acme.nl";

    private sealed class OptionsRecordingModel : IChatClient
    {
        public ChatOptions? Received { get; private set; }

        public Task<ChatResponse> GetResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, CancellationToken cancellationToken = default)
        {
            Received = options;
            return Task.FromResult(new ChatResponse(new ChatMessage(ChatRole.Assistant, "Writing to " + Placeholders.FirstSeen(options?.Instructions ?? string.Empty, "[EMAIL_1]"))));
        }

        public async IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(
            IEnumerable<ChatMessage> messages,
            ChatOptions? options = null,
            [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            var response = await GetResponseAsync(messages, options, cancellationToken);
            yield return new ChatResponseUpdate(ChatRole.Assistant, response.Text);
        }

        public object? GetService(Type serviceType, object? serviceKey = null) => null;

        public void Dispose() { }
    }

    private static (IChatClient Client, RingBufferAuditStore Audit) Build(IChatClient model)
    {
        var audit = new RingBufferAuditStore();
        var sc = new ServiceCollection();
        sc.AddAISentinel();
        sc.AddSingleton<IAuditStore>(audit);
        return (new ChatClientBuilder(model).UseAISentinel().Build(sc.BuildServiceProvider()), audit);
    }

    [Fact]
    public async Task Instructions_AreRedacted_InACopy_AndTheReplyIsRestored()
    {
        var model = new OptionsRecordingModel();
        var (client, audit) = Build(model);
        var tools = new List<AITool>();
        var options = new ChatOptions { Instructions = $"The operator is {Email}.", Tools = tools, Temperature = 0.5f };

        var response = await client.GetResponseAsync([new ChatMessage(ChatRole.User, "who is the operator?")], options, TestContext.Current.CancellationToken);

        Assert.NotNull(model.Received);
        Assert.NotSame(options, model.Received);
        Assert.Equal("The operator is [EMAIL_1].", Placeholders.Untag(model.Received!.Instructions));
        Assert.Equal(0.5f, model.Received.Temperature);
        // The caller's options are never mutated.
        Assert.Equal($"The operator is {Email}.", options.Instructions);
        Assert.Same(tools, options.Tools);
        Assert.Equal($"Writing to {Email}", response.Text);
        var entry = Assert.Single(await RecordingAuditForwarder.ReadAllAsync(audit));
        Assert.Equal("Redacted 1 EMAIL", entry.Summary);
    }

    [Fact]
    public async Task Instructions_AreRedacted_WhenStreaming()
    {
        var model = new OptionsRecordingModel();
        var (client, _) = Build(model);
        var options = new ChatOptions { Instructions = $"The operator is {Email}." };

        var text = new System.Text.StringBuilder();
        await foreach (var u in client.GetStreamingResponseAsync([new ChatMessage(ChatRole.User, "who?")], options, TestContext.Current.CancellationToken))
        {
            text.Append(u.Text);
        }

        Assert.Equal("The operator is [EMAIL_1].", Placeholders.Untag(model.Received!.Instructions));
        Assert.Equal($"The operator is {Email}.", options.Instructions);
        Assert.Equal($"Writing to {Email}", text.ToString());
    }

    [Fact]
    public async Task OptionsWithoutValues_ArePassedAsTheyAre()
    {
        var model = new OptionsRecordingModel();
        var (client, _) = Build(model);
        var options = new ChatOptions { Instructions = "Be brief." };

        await client.GetResponseAsync([new ChatMessage(ChatRole.User, "hi")], options, TestContext.Current.CancellationToken);

        Assert.Same(options, model.Received);
    }
}
