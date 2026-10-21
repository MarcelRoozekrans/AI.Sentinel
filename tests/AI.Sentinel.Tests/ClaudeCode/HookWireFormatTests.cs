using System.Text.Json;
using AI.Sentinel.ClaudeCode;
using AI.Sentinel.ClaudeCode.Cli;
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
    public void HookOutput_NewMembersNull_PinnedJsonUnchanged()
    {
        var allow = JsonSerializer.Serialize(
            new HookOutput { Decision = HookDecision.Allow, UpdatedToolOutput = null, Redactions = null },
            HookJsonContext.Default.HookOutput);

        Assert.Equal("""{"decision":"Allow","reason":null}""", allow);
    }

    private static string Wire(HookEvent evt, HookOutput output)
    {
        var wire = ClaudeCodeWireOutput.From(evt, output);
        Assert.NotNull(wire);
        return JsonSerializer.Serialize(wire, ClaudeCodeWireJsonContext.Default.ClaudeCodeWireOutput);
    }

    [Fact]
    public void ClaudeCodeWire_Allow_IsEmptyObject()
    {
        Assert.Equal("{}", Wire(HookEvent.PreToolUse, new HookOutput { Decision = HookDecision.Allow }));
        Assert.Equal("{}", Wire(HookEvent.UserPromptSubmit, new HookOutput { Decision = HookDecision.Allow }));
        Assert.Equal("{}", Wire(HookEvent.PostToolUse, new HookOutput { Decision = HookDecision.Allow }));
    }

    [Theory]
    [InlineData(HookEvent.UserPromptSubmit)]
    [InlineData(HookEvent.PreToolUse)]
    [InlineData(HookEvent.PostToolUse)]
    public void ClaudeCodeWire_Warn_IsSystemMessage(HookEvent evt)
    {
        Assert.Equal(
            """{"systemMessage":"AI.Sentinel: r"}""",
            Wire(evt, new HookOutput { Decision = HookDecision.Warn, Reason = "r" }));
    }

    [Theory]
    [InlineData(HookEvent.UserPromptSubmit)]
    [InlineData(HookEvent.PreToolUse)]
    public void ClaudeCodeWire_PreToolUseBlock_IsNull(HookEvent evt)
    {
        Assert.Null(ClaudeCodeWireOutput.From(evt, new HookOutput { Decision = HookDecision.Block, Reason = "r" }));
    }

    [Fact]
    public void ClaudeCodeWire_PostToolUseRedacted()
    {
        var output = new HookOutput
        {
            Decision = HookDecision.Allow,
            UpdatedToolOutput = JsonDocument.Parse("""{"content":"mail [EMAIL_1_k3f9x2]","n":3}""").RootElement,
            Redactions = new Dictionary<string, int>(StringComparer.Ordinal) { ["EMAIL"] = 1 },
        };

        Assert.Equal(
            """{"hookSpecificOutput":{"hookEventName":"PostToolUse","updatedToolOutput":{"content":"mail [EMAIL_1_k3f9x2]","n":3},"additionalContext":"AI.Sentinel redacted 1 EMAIL in this tool output. Placeholders such as [EMAIL_n_tag] stand for the real values; do not write them to files or commands."}}""",
            Wire(HookEvent.PostToolUse, output));
    }

    [Fact]
    public void ClaudeCodeWire_PostToolUseRedacted_ListsTypesInOrdinalOrder()
    {
        var output = new HookOutput
        {
            Decision = HookDecision.Allow,
            UpdatedToolOutput = HookPipelineRunner.JsonString("x"),
            Redactions = new Dictionary<string, int>(StringComparer.Ordinal) { ["EMAIL"] = 1, ["API_KEY"] = 1 },
        };

        var wire = ClaudeCodeWireOutput.From(HookEvent.PostToolUse, output);

        Assert.Equal(
            "AI.Sentinel redacted 1 API_KEY, 1 EMAIL in this tool output. Placeholders such as [API_KEY_n_tag], [EMAIL_n_tag] stand for the real values; do not write them to files or commands.",
            wire!.HookSpecificOutput!.AdditionalContext);
    }

    [Fact]
    public void ClaudeCodeWire_PostToolUseRedactedWithWarn_CarriesBoth()
    {
        var output = new HookOutput
        {
            Decision = HookDecision.Warn,
            Reason = "r",
            UpdatedToolOutput = HookPipelineRunner.JsonString("x"),
            Redactions = new Dictionary<string, int>(StringComparer.Ordinal) { ["EMAIL"] = 1 },
        };

        Assert.Equal(
            """{"systemMessage":"AI.Sentinel: r","hookSpecificOutput":{"hookEventName":"PostToolUse","updatedToolOutput":"x","additionalContext":"AI.Sentinel redacted 1 EMAIL in this tool output. Placeholders such as [EMAIL_n_tag] stand for the real values; do not write them to files or commands."}}""",
            Wire(HookEvent.PostToolUse, output));
    }

    [Fact]
    public void ClaudeCodeWire_PostToolUseBlock_WithholdsOutput()
    {
        var output = new HookOutput
        {
            Decision = HookDecision.Block,
            Reason = "r",
            UpdatedToolOutput = HookPipelineRunner.JsonString(HookPipelineRunner.WithheldPrefix + "r"),
        };

        Assert.Equal(
            """{"decision":"block","reason":"r","hookSpecificOutput":{"hookEventName":"PostToolUse","updatedToolOutput":"withheld by AI.Sentinel: r","additionalContext":"r"}}""",
            Wire(HookEvent.PostToolUse, output));
    }

    [Fact]
    public void WithheldOutput_KeepsShapeTypesAndEmptyStrings_ReplacesOtherStringLeaves()
    {
        var response = JsonDocument.Parse("""{"type":"text","file":{"filePath":"/a/.env","content":"secret","numLines":2,"ok":true,"none":null,"empty":"","lines":["a","",1,{"type":"x"}],"meta":{"type":{"name":"secret"}}}}""").RootElement;

        var withheld = HookPipelineRunner.WithheldOutput(response, "r");

        Assert.Equal(
            """{"type":"text","file":{"filePath":"withheld by AI.Sentinel: r","content":"withheld by AI.Sentinel: r","numLines":2,"ok":true,"none":null,"empty":"","lines":["withheld by AI.Sentinel: r","",1,{"type":"x"}],"meta":{"type":{"name":"withheld by AI.Sentinel: r"}}}}""",
            withheld.GetRawText());
    }

    // Live check: a Bash response's empty stderr stays empty, or Claude Code shows the notice twice.
    [Fact]
    public void WithheldOutput_BashShape_NoticeOnceEmptyStderrKept()
    {
        var response = JsonDocument.Parse("""{"stdout":"secret","stderr":"","interrupted":false,"isImage":false,"noOutputExpected":false}""").RootElement;

        Assert.Equal(
            """{"stdout":"withheld by AI.Sentinel: r","stderr":"","interrupted":false,"isImage":false,"noOutputExpected":false}""",
            HookPipelineRunner.WithheldOutput(response, "r").GetRawText());
    }

    [Fact]
    public void WithheldOutput_BareStringOrAbsent_IsTheWithheldString()
    {
        Assert.Equal("withheld by AI.Sentinel: r", HookPipelineRunner.WithheldOutput(HookPipelineRunner.JsonString("secret"), "r").GetString());
        Assert.Equal("withheld by AI.Sentinel: r", HookPipelineRunner.WithheldOutput(default, "r").GetString());
        Assert.Equal("withheld by AI.Sentinel: r", HookPipelineRunner.WithheldOutput(HookPipelineRunner.JsonString(""), "r").GetString());
        Assert.Equal("withheld by AI.Sentinel: r", HookPipelineRunner.WithheldOutput(JsonDocument.Parse("null").RootElement, "r").GetString());
    }

    [Fact]
    public void JsonString_EscapesAndRoundTrips()
    {
        var element = HookPipelineRunner.JsonString("a \"quoted\" line\nnext");

        Assert.Equal(JsonValueKind.String, element.ValueKind);
        Assert.Equal("a \"quoted\" line\nnext", element.GetString());
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
    public void Copilot_CamelCasePayload_ReadsToolArgsAndToolResult()
    {
        const string json = """
            {"sessionId":"c-1","toolName":"bash","toolArgs":{"command":"ls"},"toolResult":{"resultType":"success","textResultForLlm":"ok"}}
            """;

        var input = JsonSerializer.Deserialize(json, CopilotHookJsonContext.Default.CopilotHookInput);

        Assert.NotNull(input);
        Assert.Equal("""{"command":"ls"}""", input!.ToolArgs?.GetRawText());
        Assert.Equal("""{"resultType":"success","textResultForLlm":"ok"}""", input.ToolResult?.GetRawText());
    }

    [Fact]
    public void Copilot_UserPromptTransformedPayload_ReadsTransformedPrompt()
    {
        const string json = """
            {"sessionId":"c-1","prompt":"hi","transformedPrompt":"hi there"}
            """;

        var input = JsonSerializer.Deserialize(json, CopilotHookJsonContext.Default.CopilotHookInput);

        Assert.NotNull(input);
        Assert.Equal("hi there", input!.TransformedPrompt);
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
