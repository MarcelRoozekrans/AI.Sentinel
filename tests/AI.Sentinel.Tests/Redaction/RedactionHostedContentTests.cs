using System.Text.Json;
using AI.Sentinel.Detectors.Security;
using AI.Sentinel.Redaction;
using Microsoft.Extensions.AI;
using Xunit;

namespace AI.Sentinel.Tests.Redaction;

/// <summary>
/// Contents of tools a service hosts: MCP server, code interpreter, web search and image generation calls and
/// results, and approvals that carry them. They are redacted on the way to the model; on the way back a call
/// follows the tool rule unless a result answers it, and a result is restored fully.
/// </summary>
public class RedactionHostedContentTests
{
    private const string Text = "jan@acme.nl api_key=abc123def456";
    private const string Redacted = "[EMAIL_1_abc123] api_key=[API_KEY_1_abc123]";
    private const string ToolRestored = "jan@acme.nl api_key=[API_KEY_1_abc123]";

    private static RedactionSession Session() =>
        new([new PiiLeakageDetector(), new CredentialExposureDetector()], "abc123");

    private static McpServerToolCallContent McpCall() =>
        new("c1", "lookup", "crm") { Arguments = new Dictionary<string, object?>(StringComparer.Ordinal) { ["q"] = Text } };

    private static McpServerToolResultContent McpResult() =>
        new("c1") { Outputs = [new TextContent(Text)] };

    private static T Single<T>(IReadOnlyList<ChatMessage> messages, int index = 0) =>
        Assert.IsType<T>(messages[index].Contents[0]);

    private static T Single<T>(IList<ChatMessage> messages, int index = 0) =>
        Assert.IsType<T>(messages[index].Contents[0]);

    [Fact]
    public void McpServerToolCall_ArgumentsRedacted_UnansweredRestore_PiiYesSecretNo()
    {
        var session = Session();
        var call = McpCall();

        var redacted = session.Redact([new ChatMessage(ChatRole.Assistant, [call])]);

        var redactedCall = Single<McpServerToolCallContent>(redacted);
        Assert.Equal(Redacted, redactedCall.Arguments!["q"]);
        Assert.Equal(Text, call.Arguments!["q"]);

        var restored = session.Restore(new List<ChatMessage> { new(ChatRole.Assistant, [redactedCall]) });
        Assert.Equal(ToolRestored, Single<McpServerToolCallContent>(restored).Arguments!["q"]);
    }

    [Fact]
    public void McpServerToolCall_AnsweredByResult_RestoredFully()
    {
        var session = Session();
        var redacted = session.Redact(
        [
            new ChatMessage(ChatRole.Assistant, [McpCall()]),
            new ChatMessage(ChatRole.Assistant, [McpResult()]),
        ]);
        Assert.Equal(Redacted, Single<McpServerToolCallContent>(redacted).Arguments!["q"]);

        var restored = session.Restore(new List<ChatMessage>(redacted));

        Assert.Equal(Text, Single<McpServerToolCallContent>(restored).Arguments!["q"]);
    }

    [Fact]
    public void McpServerToolResult_OutputsRedactedAndRestored()
    {
        var session = Session();
        var result = McpResult();

        var redacted = session.Redact([new ChatMessage(ChatRole.Assistant, [result])]);

        var redactedResult = Single<McpServerToolResultContent>(redacted);
        Assert.Equal(Redacted, Assert.IsType<TextContent>(Assert.Single(redactedResult.Outputs!)).Text);
        Assert.Equal(Text, ((TextContent)result.Outputs![0]).Text);

        var restored = session.Restore(new List<ChatMessage> { new(ChatRole.Assistant, [redactedResult]) });
        var output = Single<McpServerToolResultContent>(restored).Outputs!;
        Assert.Equal(Text, Assert.IsType<TextContent>(Assert.Single(output)).Text);
    }

    [Fact]
    public void CodeInterpreterCallAndResult_Redacted()
    {
        var session = Session();
        var call = new CodeInterpreterToolCallContent("c1") { Inputs = [new TextContent(Text)] };
        var result = new CodeInterpreterToolResultContent("c1") { Outputs = [new TextContent(Text)] };

        var redacted = session.Redact([new ChatMessage(ChatRole.Assistant, [call, result])]);

        var redactedCall = Assert.IsType<CodeInterpreterToolCallContent>(redacted[0].Contents[0]);
        var redactedResult = Assert.IsType<CodeInterpreterToolResultContent>(redacted[0].Contents[1]);
        Assert.Equal(Redacted, ((TextContent)redactedCall.Inputs![0]).Text);
        Assert.Equal(Redacted, ((TextContent)redactedResult.Outputs![0]).Text);
        Assert.Equal(Text, ((TextContent)call.Inputs![0]).Text);

        // Unanswered, the call's inputs follow the tool rule; the result is restored fully.
        var restored = session.Restore(new List<ChatMessage>
        {
            new(ChatRole.Assistant, [redactedCall]),
            new(ChatRole.Assistant, [new CodeInterpreterToolResultContent("other") { Outputs = redactedResult.Outputs }]),
        });
        Assert.Equal(ToolRestored, ((TextContent)Single<CodeInterpreterToolCallContent>(restored).Inputs![0]).Text);
        Assert.Equal(Text, ((TextContent)Single<CodeInterpreterToolResultContent>(restored, 1).Outputs![0]).Text);
    }

    [Fact]
    public void WebSearchQueriesAndResult_Redacted()
    {
        var session = Session();
        var call = new WebSearchToolCallContent("c1") { Queries = [Text] };
        var result = new WebSearchToolResultContent("c1") { Outputs = [new TextContent(Text)] };

        var redacted = session.Redact([new ChatMessage(ChatRole.Assistant, [call, result])]);

        var redactedCall = Assert.IsType<WebSearchToolCallContent>(redacted[0].Contents[0]);
        var redactedResult = Assert.IsType<WebSearchToolResultContent>(redacted[0].Contents[1]);
        Assert.Equal(Redacted, Assert.Single(redactedCall.Queries!));
        Assert.Equal(Redacted, ((TextContent)redactedResult.Outputs![0]).Text);
        Assert.Equal(Text, call.Queries![0]);

        var unanswered = session.Restore(new List<ChatMessage> { new(ChatRole.Assistant, [redactedCall]) });
        Assert.Equal(ToolRestored, Single<WebSearchToolCallContent>(unanswered).Queries![0]);

        var answered = session.Restore(new List<ChatMessage> { new(ChatRole.Assistant, [redactedCall, redactedResult]) });
        Assert.Equal(Text, Single<WebSearchToolCallContent>(answered).Queries![0]);
        Assert.Equal(Text, ((TextContent)Assert.IsType<WebSearchToolResultContent>(answered[0].Contents[1]).Outputs![0]).Text);
    }

    [Fact]
    public void ImageGenerationResult_TextOutputRedacted_CallPassesThrough()
    {
        var session = Session();
        var call = new ImageGenerationToolCallContent("c1");
        var image = new DataContent(new byte[] { 1, 2, 3 }, "image/png");
        var result = new ImageGenerationToolResultContent("c1") { Outputs = [image, new TextContent(Text)] };

        var redacted = session.Redact([new ChatMessage(ChatRole.Assistant, [call, result])]);

        Assert.Same(call, redacted[0].Contents[0]);
        var redactedResult = Assert.IsType<ImageGenerationToolResultContent>(redacted[0].Contents[1]);
        Assert.NotSame(result, redactedResult);
        Assert.Same(image, redactedResult.Outputs![0]);
        Assert.Equal(Redacted, ((TextContent)redactedResult.Outputs[1]).Text);

        var restored = session.Restore(new List<ChatMessage> { new(ChatRole.Assistant, [redactedResult]) });
        Assert.Equal(Text, ((TextContent)Single<ImageGenerationToolResultContent>(restored).Outputs![1]).Text);
    }

    [Fact]
    public void ApprovalRequest_WithMcpServerToolCall_RedactedThenRestoredByToolRule()
    {
        var session = Session();
        var request = new ToolApprovalRequestContent("r1", McpCall());

        var redacted = session.Redact([new ChatMessage(ChatRole.Assistant, [request])]);

        var redactedRequest = Single<ToolApprovalRequestContent>(redacted);
        Assert.Equal("r1", redactedRequest.RequestId);
        var redactedCall = Assert.IsType<McpServerToolCallContent>(redactedRequest.ToolCall);
        Assert.Equal(Redacted, redactedCall.Arguments!["q"]?.ToString());
        Assert.Equal(Text, ((McpServerToolCallContent)request.ToolCall).Arguments!["q"]);

        // A result for c1 does not make the approval history: the call still waits for approval.
        var restored = session.Restore(new List<ChatMessage>
        {
            new(ChatRole.Assistant, [redactedRequest]),
            new(ChatRole.Assistant, [new McpServerToolResultContent("c1")]),
        });

        var restoredRequest = Single<ToolApprovalRequestContent>(restored);
        Assert.NotSame(redactedRequest, restoredRequest);
        var restoredCall = Assert.IsType<McpServerToolCallContent>(restoredRequest.ToolCall);
        Assert.Equal(("c1", "lookup", "crm"), (restoredCall.CallId, restoredCall.Name, restoredCall.ServerName));
        Assert.Equal(ToolRestored, restoredCall.Arguments!["q"]?.ToString());
        Assert.Equal(Redacted, redactedCall.Arguments!["q"]?.ToString());
    }

    [Fact]
    public void ApprovalResponse_WithMcpServerToolCall_RedactedThenRestoredByToolRule()
    {
        var session = Session();
        var response = new ToolApprovalResponseContent("r1", approved: true, McpCall()) { Reason = "ok for jan@acme.nl" };

        var redacted = session.Redact([new ChatMessage(ChatRole.User, [response])]);

        var redactedResponse = Single<ToolApprovalResponseContent>(redacted);
        Assert.True(redactedResponse.Approved);
        Assert.Equal("ok for [EMAIL_1_abc123]", redactedResponse.Reason);
        var redactedCall = Assert.IsType<McpServerToolCallContent>(redactedResponse.ToolCall);
        Assert.Equal(Redacted, redactedCall.Arguments!["q"]);
        Assert.Equal(Text, ((McpServerToolCallContent)response.ToolCall).Arguments!["q"]);

        var restored = session.Restore(new List<ChatMessage>
        {
            new(ChatRole.User, [redactedResponse]),
            new(ChatRole.Assistant, [new McpServerToolResultContent("c1")]),
        });

        var restoredResponse = Single<ToolApprovalResponseContent>(restored);
        Assert.Equal("ok for jan@acme.nl", restoredResponse.Reason);
        Assert.Equal(ToolRestored, Assert.IsType<McpServerToolCallContent>(restoredResponse.ToolCall).Arguments!["q"]);
    }

    [Fact]
    public void HostedCopies_KeepCallIdNameServerNameAndMetadata()
    {
        var session = Session();
        var properties = new AdditionalPropertiesDictionary { ["k"] = "v" };
        var raw = new object();
        var call = McpCall();
        call.AdditionalProperties = properties;
        call.RawRepresentation = raw;
        var result = McpResult();
        result.AdditionalProperties = properties;
        result.RawRepresentation = raw;
        var search = new WebSearchToolCallContent("c2") { Queries = [Text], RawRepresentation = raw };

        var redacted = session.Redact([new ChatMessage(ChatRole.Assistant, [call, result, search])]);

        var redactedCall = Assert.IsType<McpServerToolCallContent>(redacted[0].Contents[0]);
        Assert.NotSame(call, redactedCall);
        Assert.Equal(("c1", "lookup", "crm"), (redactedCall.CallId, redactedCall.Name, redactedCall.ServerName));
        Assert.Same(properties, redactedCall.AdditionalProperties);
        Assert.Same(raw, redactedCall.RawRepresentation);
        var redactedResult = Assert.IsType<McpServerToolResultContent>(redacted[0].Contents[1]);
        Assert.NotSame(result, redactedResult);
        Assert.Equal("c1", redactedResult.CallId);
        Assert.Same(properties, redactedResult.AdditionalProperties);
        Assert.Same(raw, redactedResult.RawRepresentation);
        var redactedSearch = Assert.IsType<WebSearchToolCallContent>(redacted[0].Contents[2]);
        Assert.Equal("c2", redactedSearch.CallId);
        Assert.Same(raw, redactedSearch.RawRepresentation);

        // The approval copy goes through JSON; the call inside it keeps its identity and metadata too.
        var request = new ToolApprovalRequestContent("r1", call);
        var redactedRequest = Single<ToolApprovalRequestContent>(session.Redact([new ChatMessage(ChatRole.Assistant, [request])]));
        var approvalCall = Assert.IsType<McpServerToolCallContent>(redactedRequest.ToolCall);
        Assert.NotSame(call, approvalCall);
        Assert.Equal(("c1", "lookup", "crm"), (approvalCall.CallId, approvalCall.Name, approvalCall.ServerName));
        Assert.Same(properties, approvalCall.AdditionalProperties);
        Assert.Same(raw, approvalCall.RawRepresentation);
        Assert.Equal(Redacted, approvalCall.Arguments!["q"]?.ToString());
        Assert.DoesNotContain("abc123def456", JsonSerializer.Serialize<AIContent>(redactedRequest, AIJsonUtilities.DefaultOptions), StringComparison.Ordinal);
    }
}
