using AI.Sentinel.Detection;
using AI.Sentinel.Intervention;
using AI.Sentinel.Tests.Helpers;
using Microsoft.Extensions.AI;
using Xunit;
using static AI.Sentinel.Tests.Redaction.RedactionPipelineTests;

namespace AI.Sentinel.Tests.Redaction;

/// <summary>#434, end to end through the in-process pipeline with <see cref="FunctionInvokingChatClient"/> running the
/// tool loop, in both builder orders.</summary>
public class ToolTrafficPipelineTests
{
    private const string GithubToken = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";

    private static ChatOptions ToolReturning(string result) =>
        new() { Tools = [AIFunctionFactory.Create((string id) => result, "Lookup")] };

    private static Task<ChatResponse> AskAsync(Harness h, string prompt, ChatOptions? options) =>
        h.Client.GetResponseAsync([new ChatMessage(ChatRole.User, prompt)], options, TestContext.Current.CancellationToken);

    /// <summary>With redaction on, the default, a secret in a tool result is replaced before the model sees it.</summary>
    [Theory]
    [MemberData(nameof(Orders), MemberType = typeof(RedactionPipelineTests))]
    public async Task SecretInToolResult_IsRedactedBeforeTheModelSeesIt(string order)
    {
        var h = Build(order, RecordingModel.CallsTool("Lookup", "id", "42", "done"));

        await AskAsync(h, "look up 42", ToolReturning($"token {GithubToken}"));

        Assert.DoesNotContain(GithubToken, h.Model.RawSeen, StringComparison.Ordinal);
        Assert.Contains("token [", h.Model.AllSeen, StringComparison.Ordinal);
    }

    /// <summary>With redaction off, a secret in a tool result is a Critical finding, which quarantines the call. Inside the
    /// tool loop, F>S, Sentinel scans each round trip, so the request carrying the result never reaches the model.
    /// Outside it, S>F, Sentinel scans the request and the loop's response once, so it finds the result after the
    /// model has seen it and quarantines the response instead.</summary>
    [Theory]
    [InlineData("F>S", false)]
    [InlineData("S>F", true)]
    public async Task SecretInToolResult_RedactionOff_IsFoundAndQuarantined(string order, bool modelSawIt)
    {
        var h = Build(order, RecordingModel.CallsTool("Lookup", "id", "42", "done"), o => o.RedactByDefault = false);

        await Assert.ThrowsAsync<SentinelException>(() => AskAsync(h, "look up 42", ToolReturning($"token {GithubToken}")));

        Assert.Equal(modelSawIt, h.Model.RawSeen.Contains(GithubToken, StringComparison.Ordinal));
        var entries = await RecordingAuditForwarder.ReadAllAsync(h.Audit);
        Assert.Contains(entries, e => string.Equals(e.DetectorId, "SEC-02", StringComparison.Ordinal) && e.Severity == Severity.Critical);
    }

    /// <summary>A credential the model puts in a tool call's arguments is a Critical finding. Inside the tool loop,
    /// F>S, the response carrying the call is quarantined before the tool runs; outside it, S>F, the call is found on
    /// the loop's response, after the tool ran.</summary>
    [Theory]
    [InlineData("F>S", false)]
    [InlineData("S>F", true)]
    public async Task SecretInToolCallArguments_IsFound(string order, bool toolRan)
    {
        var ran = false;
        var options = new ChatOptions { Tools = [AIFunctionFactory.Create((string token) => { ran = true; return "ok"; }, "Deploy")] };
        var h = Build(order, RecordingModel.CallsTool("Deploy", "token", GithubToken, "done"), o => o.RedactByDefault = false);

        await Assert.ThrowsAsync<SentinelException>(() => AskAsync(h, "deploy please", options));

        Assert.Equal(toolRan, ran);
        var entries = await RecordingAuditForwarder.ReadAllAsync(h.Audit);
        Assert.Contains(entries, e => string.Equals(e.DetectorId, "SEC-02", StringComparison.Ordinal) && e.Severity == Severity.Critical);
    }

    /// <summary>An approval-required tool: <see cref="FunctionInvokingChatClient"/> hands the caller a
    /// <see cref="ToolApprovalRequestContent"/> in place of the call. Outside the loop, S>F, that request is all Sentinel
    /// sees of the call, so its arguments are judged there, before anyone approves the call; inside it, F>S, Sentinel
    /// sees the model's call itself.</summary>
    [Theory]
    [MemberData(nameof(Orders), MemberType = typeof(RedactionPipelineTests))]
    public async Task SecretInApprovalRequiredToolCallArguments_IsFoundBeforeApproval(string order)
    {
        var ran = false;
        var tool = new ApprovalRequiredAIFunction(AIFunctionFactory.Create((string token) => { ran = true; return "ok"; }, "Deploy"));
        var options = new ChatOptions { Tools = [tool] };
        var h = Build(order, RecordingModel.CallsTool("Deploy", "token", GithubToken, "done"), o => o.RedactByDefault = false);

        await Assert.ThrowsAsync<SentinelException>(() => AskAsync(h, "deploy please", options));

        Assert.False(ran);
        var entries = await RecordingAuditForwarder.ReadAllAsync(h.Audit);
        Assert.Contains(entries, e => string.Equals(e.DetectorId, "SEC-02", StringComparison.Ordinal) && e.Severity == Severity.Critical);
    }

    /// <summary>Without a finding, S>F hands the caller the approval request, not the call: the case the test above covers.</summary>
    [Fact]
    public async Task ApprovalRequiredTool_OutsideTheLoop_CallerGetsAnApprovalRequest()
    {
        var tool = new ApprovalRequiredAIFunction(AIFunctionFactory.Create((string id) => "ok", "Lookup"));
        var h = Build("S>F", RecordingModel.CallsTool("Lookup", "id", "42", "done"));

        var response = await AskAsync(h, "look up 42", new ChatOptions { Tools = [tool] });

        Assert.Contains(response.Messages.SelectMany(m => m.Contents), c => c is ToolApprovalRequestContent);
        Assert.DoesNotContain(response.Messages.SelectMany(m => m.Contents), c => c is FunctionCallContent);
    }
}
