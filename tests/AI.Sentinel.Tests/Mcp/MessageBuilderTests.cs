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

        var messages = MessageBuilder.BuildToolCallRequest(req, maxScanBytes: 1024);

        var msg = Assert.Single(messages);
        Assert.Equal(ChatRole.User, msg.Role);
        Assert.Contains("tool:read_file", msg.Text, StringComparison.Ordinal);
        Assert.Contains("/tmp/hello.txt", msg.Text, StringComparison.Ordinal);
    }

    [Fact]
    public void BuildToolCallRequest_OversizeArguments_Truncates()
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

        var messages = MessageBuilder.BuildToolCallRequest(req, maxScanBytes: 256);

        var msg = Assert.Single(messages);
        Assert.Contains("[truncated", msg.Text, StringComparison.Ordinal);
        Assert.True(msg.Text.Length < 4096);
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

        var messages = MessageBuilder.BuildToolCallResponse(req, result, maxScanBytes: 1024);

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

        var messages = MessageBuilder.BuildToolCallResponse(req, result, maxScanBytes: 1024);

        Assert.Single(messages);
        Assert.Equal(ChatRole.User, messages[0].Role);
    }

    [Fact]
    public void BuildToolCallResponse_OversizeText_Truncates()
    {
        var req = new CallToolRequestParams { Name = "read_huge" };
        var longText = new string('x', 8192);
        var result = new CallToolResult
        {
            Content = [new TextContentBlock { Text = longText }],
        };

        var messages = MessageBuilder.BuildToolCallResponse(req, result, maxScanBytes: 1024);

        Assert.Equal(2, messages.Length);
        Assert.Contains("[truncated", messages[1].Text, StringComparison.Ordinal);
        Assert.True(messages[1].Text.Length < 8192);
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

        var messages = MessageBuilder.BuildPromptGetResponse(result, maxScanBytes: 1024);

        var single = Assert.Single(messages);
        Assert.Equal(ChatRole.Assistant, single.Role);
        Assert.Contains("hello", single.Text, StringComparison.Ordinal);
        Assert.Contains("world", single.Text, StringComparison.Ordinal);
    }

    [Fact]
    public void BuildToolCallResponse_TextExactlyAtLimit_NotTruncated()
    {
        var req = new CallToolRequestParams { Name = "read_exact" };
        var exactText = new string('x', 1024);   // exactly maxScanBytes
        var result = new CallToolResult
        {
            Content = [new TextContentBlock { Text = exactText }],
        };

        var messages = MessageBuilder.BuildToolCallResponse(req, result, maxScanBytes: 1024);

        Assert.Equal(2, messages.Length);
        Assert.DoesNotContain("[truncated", messages[1].Text, StringComparison.Ordinal);
        Assert.Contains(exactText, messages[1].Text, StringComparison.Ordinal);
    }
}
