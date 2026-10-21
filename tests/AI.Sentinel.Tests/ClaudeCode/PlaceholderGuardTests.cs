using System.Text.Json;
using Xunit;
using AI.Sentinel.ClaudeCode;

namespace AI.Sentinel.Tests.ClaudeCode;

public class PlaceholderGuardTests
{
    private const string Placeholder = "[EMAIL_2_q7m4zt]";

    private static JsonElement Json(string json)
    {
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.Clone();
    }

    private static HookOutput? Check(string toolName, string toolInput) =>
        PlaceholderGuard.Check(toolName, Json(toolInput), PlaceholderGuard.ClaudeCodeTools);

    [Fact]
    public void Write_WithPlaceholderInContent_Denied()
    {
        var output = Check("Write", $$"""{"file_path":"/a/b.txt","content":"mail {{Placeholder}} today"}""");

        Assert.NotNull(output);
        Assert.Equal(HookDecision.Block, output.Decision);
        Assert.Equal(PlaceholderGuard.Reason, output.Reason);
    }

    [Fact]
    public void Bash_WithPlaceholderInCommand_Denied()
    {
        var output = Check("Bash", $$"""{"command":"echo {{Placeholder}} >> out.txt"}""");

        Assert.Equal(HookDecision.Block, output?.Decision);
    }

    [Fact]
    public void NestedPlaceholderInMultiEditEdits_Denied()
    {
        var output = Check("MultiEdit",
            $$"""{"file_path":"/a/b.txt","edits":[{"old_string":"x","new_string":"y"},{"old_string":"a","new_string":"to {{Placeholder}}"}]}""");

        Assert.Equal(HookDecision.Block, output?.Decision);
    }

    [Fact]
    public void Read_WithPlaceholder_Allowed()
    {
        Assert.Null(Check("Read", $$"""{"file_path":"/a/{{Placeholder}}.txt"}"""));
    }

    [Fact]
    public void Write_WithoutPlaceholder_Allowed()
    {
        Assert.Null(Check("Write", """{"file_path":"/a/b.txt","content":"plain [text] here"}"""));
    }

    [Fact]
    public void UntaggedLookalike_EMAIL_1_Allowed()
    {
        Assert.Null(Check("Write", """{"file_path":"/a/b.txt","content":"see [EMAIL_1] for the shape"}"""));
    }

    [Fact]
    public void ToolNameCaseMismatch_write_NotGuardedForClaudeCode()
    {
        Assert.Null(Check("write", $$"""{"file_path":"/a/b.txt","content":"{{Placeholder}}"}"""));
    }

    [Fact]
    public void StringRoot_WithPlaceholder_Denied()
    {
        var output = PlaceholderGuard.Check("bash", Json($$""" "echo {{Placeholder}}" """), PlaceholderGuard.CopilotTools);

        Assert.Equal(HookDecision.Block, output?.Decision);
    }

    [Fact]
    public void NullInput_Allowed()
    {
        Assert.Null(PlaceholderGuard.Check("Write", default, PlaceholderGuard.ClaudeCodeTools));
        Assert.Null(PlaceholderGuard.Check(null, Json($$"""{"content":"{{Placeholder}}"}"""), PlaceholderGuard.ClaudeCodeTools));
    }

    [Fact]
    public void Reason_IsFixedCopy_NoInputEcho()
    {
        const string secretPath = "/home/jan/private-notes.txt";
        var output = Check("Write", $$"""{"file_path":"{{secretPath}}","content":"Dear {{Placeholder}}, see you"}""");

        Assert.NotNull(output);
        Assert.Equal(PlaceholderGuard.Reason, output.Reason);
        Assert.DoesNotContain(Placeholder, output.Reason!, StringComparison.Ordinal);
        Assert.DoesNotContain(secretPath, output.Reason!, StringComparison.Ordinal);
        Assert.DoesNotContain("Dear", output.Reason!, StringComparison.Ordinal);
        Assert.Null(output.UpdatedToolOutput);
    }
}
