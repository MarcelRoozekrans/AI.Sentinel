using System;
using System.Collections.Generic;
using System.Text.Json;
using AI.Sentinel.Mcp;
using Microsoft.Extensions.AI;
using ModelContextProtocol.Protocol;
using Xunit;

namespace AI.Sentinel.Tests.Mcp;

public class MessageBuilderTests
{
    [Fact]
    public void BuildToolCallRequest_SerializesArgumentsIntoUserMessage()
    {
        var req = new CallToolRequestParams
        {
            Name = "read_file",
            Arguments = new Dictionary<string, JsonElement>(StringComparer.Ordinal)
            {
                ["path"] = JsonDocument.Parse("\"/tmp/hello.txt\"").RootElement,
            },
        };

        var messages = MessageBuilder.BuildToolCallRequest(req);

        var msg = Assert.Single(messages);
        Assert.Equal(ChatRole.User, msg.Role);
        Assert.Contains("tool:read_file", msg.Text, StringComparison.Ordinal);
        Assert.Contains("/tmp/hello.txt", msg.Text, StringComparison.Ordinal);
    }

    // #439: the builder passes the text whole; the pipeline cuts it to MaxScanBytes and reports SEC-00.
    [Fact]
    public void BuildToolCallRequest_LargeArguments_PassedWhole()
    {
        var longValue = new string('x', 4096);
        var req = new CallToolRequestParams
        {
            Name = "write_huge",
            Arguments = new Dictionary<string, JsonElement>(StringComparer.Ordinal)
            {
                ["content"] = JsonDocument.Parse($"\"{longValue}\"").RootElement,
            },
        };

        var messages = MessageBuilder.BuildToolCallRequest(req);

        var msg = Assert.Single(messages);
        Assert.DoesNotContain("[truncated", msg.Text, StringComparison.Ordinal);
        Assert.Contains(longValue, msg.Text, StringComparison.Ordinal);
    }

    [Fact]
    public void BuildToolCallResponse_ConcatenatesTextBlocks_SkipsNonText()
    {
        var req = new CallToolRequestParams { Name = "read_file" };
        var result = new CallToolResult
        {
            Content =
            [
                new TextContentBlock { Text = "first block" },
                new ImageContentBlock
                {
                    Data = new ReadOnlyMemory<byte>(Array.Empty<byte>()),
                    MimeType = "image/png",
                },
                new TextContentBlock { Text = "second block" },
            ],
        };

        var messages = MessageBuilder.BuildToolCallResponse(req, result);

        Assert.Equal(2, messages.Length);
        Assert.Equal(ChatRole.User, messages[0].Role);
        Assert.Equal(ChatRole.Assistant, messages[1].Role);
        Assert.Contains("first block", messages[1].Text, StringComparison.Ordinal);
        Assert.Contains("second block", messages[1].Text, StringComparison.Ordinal);
        Assert.DoesNotContain("image/png", messages[1].Text, StringComparison.Ordinal);
    }

    [Fact]
    public void BuildToolCallResponse_AllNonText_ReturnsOnlyRequestContext()
    {
        var req = new CallToolRequestParams { Name = "take_photo" };
        var result = new CallToolResult
        {
            Content =
            [
                new ImageContentBlock
                {
                    Data = new ReadOnlyMemory<byte>(Array.Empty<byte>()),
                    MimeType = "image/png",
                },
            ],
        };

        var messages = MessageBuilder.BuildToolCallResponse(req, result);

        Assert.Single(messages);
        Assert.Equal(ChatRole.User, messages[0].Role);
    }

    [Fact]
    public void BuildToolCallResponse_LargeText_PassedWhole()
    {
        var req = new CallToolRequestParams { Name = "read_huge" };
        var longText = new string('x', 8192);
        var result = new CallToolResult
        {
            Content = [new TextContentBlock { Text = longText }],
        };

        var messages = MessageBuilder.BuildToolCallResponse(req, result);

        Assert.Equal(2, messages.Length);
        Assert.Equal(longText, messages[1].Text);
    }

    [Fact]
    public void BuildPromptGetResponse_LargeText_PassedWhole()
    {
        var longText = new string('x', 8192);
        var result = new GetPromptResult
        {
            Messages = [new PromptMessage { Role = Role.User, Content = new TextContentBlock { Text = longText } }],
        };

        var single = Assert.Single(MessageBuilder.BuildPromptGetResponse(result));

        Assert.Equal(longText, single.Text);
    }

    [Fact]
    public void CollectRedactable_LargeItems_AllCollected()
    {
        // 4.1 split items past the budget off as unredacted "oversize"; every allowlisted item is now redactable.
        var blocks = new List<ContentBlock>
        {
            new TextContentBlock { Text = new string('a', 300_000) },
            new TextContentBlock { Text = new string('b', 300_000) },
        };

        var (content, apply) = MessageBuilder.CollectRedactable(blocks, ResourceReadInterceptor.ParseMimeAllowlist());

        Assert.Equal(2, content.Count);
        Assert.Equal(2, apply.Count);
        Assert.Equal(300_000, content[1].Text!.Length);
    }

    [Fact]
    public void BuildPromptGetResponse_ConcatenatesAllMessagesAsAssistantRole()
    {
        var result = new GetPromptResult
        {
            Messages =
            [
                new PromptMessage
                {
                    Role = Role.User,
                    Content = new TextContentBlock { Text = "hello" },
                },
                new PromptMessage
                {
                    Role = Role.Assistant,
                    Content = new TextContentBlock { Text = "world" },
                },
            ],
        };

        var messages = MessageBuilder.BuildPromptGetResponse(result);

        var single = Assert.Single(messages);
        Assert.Equal(ChatRole.Assistant, single.Role);
        Assert.Contains("hello", single.Text, StringComparison.Ordinal);
        Assert.Contains("world", single.Text, StringComparison.Ordinal);
    }

    [Fact]
    public void BuildToolCallResponse_MultiByteText_PassedWhole()
    {
        // 80 unicorn emoji: surrogate pairs, 320 UTF-8 bytes. The builder no longer cuts anything, so none is split.
        var req = new CallToolRequestParams { Name = "read_emoji" };
        var emoji = new System.Text.StringBuilder(capacity: 160);
        for (var i = 0; i < 80; i++) emoji.Append("\U0001F984");  // 🦄
        var oversize = emoji.ToString();
        var result = new CallToolResult
        {
            Content = [new TextContentBlock { Text = oversize }],
        };

        var messages = MessageBuilder.BuildToolCallResponse(req, result);

        Assert.Equal(2, messages.Length);
        Assert.Equal(oversize, messages[1].Text);
    }
}
