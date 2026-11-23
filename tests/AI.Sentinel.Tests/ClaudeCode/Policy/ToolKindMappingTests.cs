using AI.Sentinel.ClaudeCode.Policy;
using Xunit;

namespace AI.Sentinel.Tests.ClaudeCode.Policy;

public class ToolKindMappingTests
{
    [Theory]
    [InlineData("Bash", "shell")]
    [InlineData("Read", "read")]
    [InlineData("NotebookRead", "read")]
    [InlineData("Glob", "search")]
    [InlineData("Grep", "search")]
    [InlineData("LS", "search")]
    [InlineData("Write", "write")]
    [InlineData("Edit", "edit")]
    [InlineData("MultiEdit", "edit")]
    [InlineData("NotebookEdit", "edit")]
    [InlineData("WebFetch", "fetch")]
    [InlineData("WebSearch", "fetch")]
    [InlineData("Task", "agent")]
    [InlineData("Agent", "agent")]
    [InlineData("mcp__github__create_issue", "mcp")]
    [InlineData("TodoWrite", "other")]
    [InlineData("SomethingNew", "other")]
    [InlineData("bash", "other")]
    [InlineData("", "other")]
    public void ClaudeCode_tool_maps_to_one_kind(string tool, string expected) =>
        Assert.Equal(expected, ToolKinds.Map(PolicyClis.ClaudeCode, tool).ToWire());

    [Theory]
    [InlineData("bash", "shell")]
    [InlineData("powershell", "shell")]
    [InlineData("view", "read")]
    [InlineData("glob", "search")]
    [InlineData("grep", "search")]
    [InlineData("create", "write")]
    [InlineData("edit", "edit")]
    [InlineData("str_replace_editor", "edit")]
    [InlineData("apply_patch", "edit")]
    [InlineData("web_fetch", "fetch")]
    [InlineData("task", "agent")]
    [InlineData("write_bash", "other")]
    [InlineData("ask_user", "other")]
    [InlineData("unknown_tool", "other")]
    public void Copilot_tool_maps_to_one_kind(string tool, string expected) =>
        Assert.Equal(expected, ToolKinds.Map(PolicyClis.Copilot, tool).ToWire());

    [Theory]
    [InlineData("Bash", "shell")]
    [InlineData("Write", "write")]
    [InlineData("mcp__srv__tool", "mcp")]
    public void Copilot_vscode_payload_uses_the_claude_names(string tool, string expected) =>
        Assert.Equal(expected, ToolKinds.Map(PolicyClis.Copilot, tool).ToWire());

    [Fact]
    public void Null_tool_name_and_unknown_cli_are_other()
    {
        Assert.Equal(ToolKind.Other, ToolKinds.Map(PolicyClis.ClaudeCode, null));
        Assert.Equal(ToolKind.Other, ToolKinds.Map("nope", "Bash"));
    }

    [Fact]
    public void Every_kind_has_its_wire_name()
    {
        var wire = Enum.GetValues<ToolKind>().Select(k => k.ToWire()).Order(StringComparer.Ordinal).ToArray();
        Assert.Equal(["agent", "edit", "fetch", "mcp", "other", "read", "search", "shell", "write"], wire);
    }

    [Fact]
    public void Wire_clis_are_the_names_of_the_design()
    {
        Assert.Equal("claude-code", PolicyClis.ClaudeCode);
        Assert.Equal("copilot", PolicyClis.Copilot);
    }
}
