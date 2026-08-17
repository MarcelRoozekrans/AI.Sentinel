using Xunit;
using Microsoft.Extensions.AI;
using AI.Sentinel.Cli;

namespace AI.Sentinel.Tests.Replay;

public class ConversationLoaderTests
{
    private static string Fixture(string name) =>
        Path.Combine(AppContext.BaseDirectory, "Fixtures", "conversations", name);

    [Fact]
    public async Task LoadOpenAI_ValidMessagesArray_ReturnsTurns()
    {
        var result = await ConversationLoader.LoadAsync(
            Fixture("clean-openai.json"), ConversationFormat.OpenAIChatCompletion, TestContext.Current.CancellationToken);

        Assert.Equal(ConversationFormat.OpenAIChatCompletion, result.Format);
        Assert.Single(result.Turns);
        Assert.Single(result.Turns[0].Prompt);
        Assert.Equal(ChatRole.User, result.Turns[0].Prompt[0].Role);
        Assert.Equal(ChatRole.Assistant, result.Turns[0].Response.Role);
        Assert.Contains("Paris", result.Turns[0].Response.Text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task LoadOpenAI_SplitsOnAssistantRole()
    {
        var result = await ConversationLoader.LoadAsync(
            Fixture("multi-turn-openai.json"), ConversationFormat.OpenAIChatCompletion, TestContext.Current.CancellationToken);

        Assert.Equal(2, result.Turns.Count);
        Assert.Equal("Hello!", result.Turns[0].Response.Text);
        Assert.Equal("Sunny today.", result.Turns[1].Response.Text);
        // Turn 2's prompt includes turn 1's exchange (3 messages before the final assistant turn)
        Assert.Equal(3, result.Turns[1].Prompt.Count);
    }

    [Fact]
    public async Task LoadOpenAI_NoAssistantMessages_EmptyResult()
    {
        var tempFile = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(tempFile,
                """{ "messages": [ { "role": "user", "content": "hi" } ] }""", TestContext.Current.CancellationToken);
            var result = await ConversationLoader.LoadAsync(
                tempFile, ConversationFormat.OpenAIChatCompletion, TestContext.Current.CancellationToken);
            Assert.Empty(result.Turns);
        }
        finally { File.Delete(tempFile); }
    }

    [Fact]
    public async Task LoadNdjson_OneLinePerTurn_ReturnsTurns()
    {
        var result = await ConversationLoader.LoadAsync(
            Fixture("audit.ndjson"), ConversationFormat.AuditNdjson, TestContext.Current.CancellationToken);

        Assert.Equal(2, result.Turns.Count);
        Assert.Equal("hello", result.Turns[0].Response.Text);
        Assert.Equal("goodbye", result.Turns[1].Response.Text);
    }

    [Fact]
    public async Task LoadAuto_OpenAIByContent_DetectsCorrectly()
    {
        var result = await ConversationLoader.LoadAsync(
            Fixture("clean-openai.json"), ConversationFormat.Auto, TestContext.Current.CancellationToken);
        Assert.Equal(ConversationFormat.OpenAIChatCompletion, result.Format);
    }

    [Fact]
    public async Task LoadAuto_NdjsonByExtension_DetectsCorrectly()
    {
        var result = await ConversationLoader.LoadAsync(
            Fixture("audit.ndjson"), ConversationFormat.Auto, TestContext.Current.CancellationToken);
        Assert.Equal(ConversationFormat.AuditNdjson, result.Format);
    }

    [Fact]
    public async Task LoadAuto_Ambiguous_Throws()
    {
        var tempFile = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(tempFile, "not json at all", TestContext.Current.CancellationToken);
            await Assert.ThrowsAsync<InvalidDataException>(
                () => ConversationLoader.LoadAsync(tempFile, ConversationFormat.Auto, TestContext.Current.CancellationToken));
        }
        finally { File.Delete(tempFile); }
    }
}
