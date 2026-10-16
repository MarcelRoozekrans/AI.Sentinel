using System.Text.Json;
using AI.Sentinel.ClaudeCode;
using AI.Sentinel.Copilot;
using Xunit;

namespace AI.Sentinel.Tests.ClaudeCode;

/// <summary>
/// Pins the exact JSON the hook CLIs read and write. These contracts must survive any change
/// to the shape of the C# types.
/// </summary>
public class HookWireFormatTests
{
    [Fact]
    public void ClaudeCode_PreToolUsePayload_Deserializes()
    {
        const string json = """
            {"session_id":"abc-123","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls -la"},"unknown_future_field":1}
            """;

        var input = JsonSerializer.Deserialize(json, HookJsonContext.Default.HookInput);

        Assert.NotNull(input);
        Assert.Equal("abc-123", input!.SessionId);
        Assert.Null(input.Prompt);
        Assert.Equal("Bash", input.ToolName);
        Assert.Equal("""{"command":"ls -la"}""", input.ToolInput?.GetRawText());
        Assert.Null(input.ToolResponse);
    }

    [Fact]
    public void ClaudeCode_PostToolUsePayload_Deserializes()
    {
        const string json = """
            {"session_id":"s9","tool_name":"Read","tool_input":{"file_path":"/a"},"tool_response":{"content":"hi"}}
            """;

        var input = JsonSerializer.Deserialize(json, HookJsonContext.Default.HookInput);

        Assert.Equal("s9", input!.SessionId);
        Assert.Equal("""{"content":"hi"}""", input.ToolResponse?.GetRawText());
    }

    [Fact]
    public void ClaudeCode_UserPromptSubmitPayload_Deserializes()
    {
        const string json = """{"session_id":"s1","prompt":"hello there"}""";

        var input = JsonSerializer.Deserialize(json, HookJsonContext.Default.HookInput);

        Assert.Equal("s1", input!.SessionId);
        Assert.Equal("hello there", input.Prompt);
        Assert.Null(input.ToolName);
    }

    [Fact]
    public void ClaudeCode_Input_Serializes_SnakeCase()
    {
        var input = new HookInput { SessionId = "s1", Prompt = "p", ToolName = "Bash" };

        var json = JsonSerializer.Serialize(input, HookJsonContext.Default.HookInput);

        Assert.Equal("""{"session_id":"s1","prompt":"p","tool_name":"Bash","tool_input":null,"tool_response":null}""", json);
    }

    [Fact]
    public void ClaudeCode_Output_Serializes_ExactJson()
    {
        var block = JsonSerializer.Serialize(
            new HookOutput { Decision = HookDecision.Block, Reason = "nope" }, HookJsonContext.Default.HookOutput);
        var allow = JsonSerializer.Serialize(
            new HookOutput { Decision = HookDecision.Allow }, HookJsonContext.Default.HookOutput);

        Assert.Equal("""{"decision":"Block","reason":"nope"}""", block);
        Assert.Equal("""{"decision":"Allow","reason":null}""", allow);
    }

    [Fact]
    public void Copilot_Payload_Deserializes_CamelCase()
    {
        const string json = """
            {"sessionId":"c-1","prompt":"hi","toolName":"Bash","toolInput":{"command":"ls"},"toolResponse":{"ok":true}}
            """;

        var input = JsonSerializer.Deserialize(json, CopilotHookJsonContext.Default.CopilotHookInput);

        Assert.NotNull(input);
        Assert.Equal("c-1", input!.SessionId);
        Assert.Equal("hi", input.Prompt);
        Assert.Equal("Bash", input.ToolName);
        Assert.Equal("""{"command":"ls"}""", input.ToolInput?.GetRawText());
        Assert.Equal("""{"ok":true}""", input.ToolResponse?.GetRawText());
    }

    [Fact]
    public void Copilot_Input_Serializes_CamelCase()
    {
        var input = new CopilotHookInput { SessionId = "c-1", ToolName = "Bash" };

        var json = JsonSerializer.Serialize(input, CopilotHookJsonContext.Default.CopilotHookInput);

        Assert.Equal("""{"sessionId":"c-1","prompt":null,"toolName":"Bash","toolInput":null,"toolResponse":null}""", json);
    }

    [Fact]
    public void Copilot_Output_Serializes_ExactJson()
    {
        var json = JsonSerializer.Serialize(
            new HookOutput { Decision = HookDecision.Warn, Reason = "careful" }, CopilotHookJsonContext.Default.HookOutput);

        Assert.Equal("""{"decision":"Warn","reason":"careful"}""", json);
    }
}
