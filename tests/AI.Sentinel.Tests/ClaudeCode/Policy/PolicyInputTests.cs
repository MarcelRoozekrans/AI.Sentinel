using System.Text.Json;
using AI.Sentinel.ClaudeCode.Policy;
using Xunit;

namespace AI.Sentinel.Tests.ClaudeCode.Policy;

public class PolicyInputTests
{
    private static readonly string Root = OperatingSystem.IsWindows() ? @"C:\work\repo" : "/work/repo";

    private static readonly string JsonEncodedRoot = Root.Replace("\\", "\\\\", StringComparison.Ordinal);

    private static JsonElement Build(string cli, string tool, string inputJson, params PolicyFinding[] findings)
    {
        using var doc = JsonDocument.Parse(inputJson);
        var input = PolicyInputBuilder.Build(cli, tool, doc.RootElement, "sess-1", findings, Root);
        return JsonDocument.Parse(PolicyInputSerializer.Serialize(input)).RootElement;
    }

    [Fact]
    public void Input_carries_every_field_of_the_design()
    {
        var json = Build(PolicyClis.ClaudeCode, "Bash", """{"command":"ls"}""", new PolicyFinding("SEC-01", "high"));

        Assert.Equal("shell", json.GetProperty("kind").GetString());
        Assert.Equal("claude-code", json.GetProperty("cli").GetString());
        Assert.Equal("Bash", json.GetProperty("tool").GetString());
        Assert.Equal("sess-1", json.GetProperty("session").GetString());
        Assert.Equal(JsonValueKind.Object, json.GetProperty("details").ValueKind);
        var finding = Assert.Single(json.GetProperty("findings").EnumerateArray());
        Assert.Equal("SEC-01", finding.GetProperty("detector").GetString());
        Assert.Equal("high", finding.GetProperty("severity").GetString());
    }

    [Fact]
    public void Repository_and_node_are_present_and_empty_until_later_issues_fill_them()
    {
        var json = Build(PolicyClis.Copilot, "bash", """{"command":"ls"}""");

        Assert.Equal("", json.GetProperty("repository").GetString());
        Assert.Equal("", json.GetProperty("node").GetString());
        Assert.Equal(0, json.GetProperty("findings").GetArrayLength());
    }

    [Fact]
    public void Shell_details_hold_the_parsed_commands()
    {
        var shell = Build(PolicyClis.ClaudeCode, "Bash", """{"command":"cat a | grep 'x y' && echo ok > o.txt"}""").GetProperty("details").GetProperty("shell");

        Assert.False(shell.GetProperty("unparseable").GetBoolean());
        var commands = shell.GetProperty("commands");
        Assert.Equal(3, commands.GetArrayLength());
        Assert.Equal("grep", commands[1].GetProperty("name").GetString());
        Assert.Equal("|", commands[1].GetProperty("operator").GetString());
        Assert.Equal("x y", commands[1].GetProperty("args")[0].GetString());
        Assert.Equal(">", commands[2].GetProperty("redirects")[0].GetProperty("op").GetString());
    }

    [Theory]
    [InlineData("Bash", """{"command":"echo $(whoami)"}""")]
    [InlineData("Bash", """{"command":"echo 'open"}""")]
    [InlineData("Bash", """{"description":"no command"}""")]
    [InlineData("Bash", """{"command":42}""")]
    public void Shell_command_line_that_cannot_be_parsed_is_marked_unparseable(string tool, string input)
    {
        var shell = Build(PolicyClis.ClaudeCode, tool, input).GetProperty("details").GetProperty("shell");

        Assert.True(shell.GetProperty("unparseable").GetBoolean());
        Assert.Equal(0, shell.GetProperty("commands").GetArrayLength());
    }

    [Fact]
    public void Powershell_is_marked_unparseable_because_the_parser_reads_posix_quoting()
    {
        var shell = Build(PolicyClis.Copilot, "powershell", """{"command":"Get-ChildItem C:\\x"}""").GetProperty("details").GetProperty("shell");

        Assert.True(shell.GetProperty("unparseable").GetBoolean());
    }

    [Theory]
    [InlineData("mcp__github__create_issue", "github", "create_issue")]
    [InlineData("mcp__my-server__a__b", "my-server", "a__b")]
    [InlineData("mcp__lonely", "lonely", "")]
    public void Mcp_details_hold_server_endpoint_and_tool(string tool, string server, string name)
    {
        var mcp = Build(PolicyClis.ClaudeCode, tool, "{}").GetProperty("details").GetProperty("mcp");

        Assert.Equal(server, mcp.GetProperty("server").GetString());
        Assert.Equal(name, mcp.GetProperty("tool").GetString());
        Assert.Equal("", mcp.GetProperty("endpoint").GetString());
    }

    [Theory]
    [InlineData("Read", """{"file_path":"{R}/a.cs"}""", "read", "{R}/a.cs", true)]
    [InlineData("Write", """{"file_path":"{R}/src/../b.cs","content":"x"}""", "write", "{R}/b.cs", true)]
    [InlineData("Edit", """{"file_path":"src/c.cs"}""", "edit", "{R}/src/c.cs", true)]
    [InlineData("NotebookEdit", """{"notebook_path":"{R}/n.ipynb"}""", "edit", "{R}/n.ipynb", true)]
    [InlineData("Read", """{"file_path":"/etc/passwd"}""", "read", "/etc/passwd", false)]
    [InlineData("Read", """{"file_path":"{R}/../outside.txt"}""", "read", "{R}/../outside.txt", false)]
    [InlineData("Read", """{"file_path":"{R}2/x"}""", "read", "{R}2/x", false)]
    [InlineData("Grep", """{"pattern":"x","path":"{R}/src"}""", "search", "{R}/src", true)]
    [InlineData("Read", """{"file_path":"~/.ssh/id_rsa"}""", "read", "~/.ssh/id_rsa", false)]
    public void File_kinds_give_each_path_with_an_inside_repository_flag(string tool, string input, string kind, string path, bool inside)
    {
        var json = Build(PolicyClis.ClaudeCode, tool, input.Replace("{R}", JsonEncodedRoot, StringComparison.Ordinal));
        var entry = Assert.Single(json.GetProperty("details").GetProperty("paths").EnumerateArray());

        Assert.Equal(kind, json.GetProperty("kind").GetString());
        Assert.Equal(inside, entry.GetProperty("in_repository").GetBoolean());
        var expected = path.Replace("{R}", Root, StringComparison.Ordinal);
        Assert.Equal(expected.StartsWith('~') ? expected : Path.GetFullPath(expected), entry.GetProperty("path").GetString());
    }

    [Theory]
    [InlineData("""{"command":"\uD800"}""")]
    [InlineData("\"\\uD800\"")]
    public void Undecodable_json_strings_count_as_missing_input(string inputJson)
    {
        var json = Build(PolicyClis.ClaudeCode, "Bash", inputJson);

        Assert.True(json.GetProperty("details").GetProperty("shell").GetProperty("unparseable").GetBoolean());
    }

    [Theory]
    [InlineData(@"\\?\C:\repo\notes.txt", @"C:\repo\notes.txt")]
    [InlineData(@"\\?\c:\repo", @"c:\repo")]
    [InlineData(@"\\?\UNC\server\share\a", @"\\?\UNC\server\share\a")]
    [InlineData(@"\\.\C:\repo", @"\\.\C:\repo")]
    [InlineData("/work/repo", "/work/repo")]
    public void Extended_drive_paths_compare_as_ordinary_drive_paths(string path, string expected)
    {
        Assert.Equal(expected, PolicyInputBuilder.ComparisonForm(path));
    }

    [Fact]
    public void Path_is_not_inside_when_the_repository_root_is_unknown()
    {
        using var doc = JsonDocument.Parse("""{"path":"a.cs"}""");
        var input = PolicyInputBuilder.Build(PolicyClis.Copilot, "view", doc.RootElement, "s", [], null);

        var path = Assert.Single(input.Details.Paths!);
        Assert.False(path.InRepository);
    }

    [Fact]
    public void Copilot_tool_args_sent_as_a_json_string_are_read()
    {
        var args = JsonSerializer.Serialize(JsonSerializer.Serialize(new Dictionary<string, string>(StringComparer.Ordinal) { ["path"] = Root + "/a.cs" }));
        var json = Build(PolicyClis.Copilot, "view", args);

        var entry = Assert.Single(json.GetProperty("details").GetProperty("paths").EnumerateArray());
        Assert.True(entry.GetProperty("in_repository").GetBoolean());
    }

    [Fact]
    public void Fetch_details_hold_the_url()
    {
        var details = Build(PolicyClis.ClaudeCode, "WebFetch", """{"url":"https://example.com/a","prompt":"p"}""").GetProperty("details");

        Assert.Equal("https://example.com/a", details.GetProperty("url").GetString());
    }

    [Theory]
    [InlineData("TodoWrite")]
    [InlineData("SomethingNew")]
    [InlineData("Task")]
    public void Other_and_agent_kinds_have_empty_details(string tool)
    {
        var details = Build(PolicyClis.ClaudeCode, tool, """{"todos":[],"prompt":"do it"}""").GetProperty("details");

        Assert.Empty(details.EnumerateObject());
    }

    [Fact]
    public void Missing_tool_input_does_not_throw()
    {
        var input = PolicyInputBuilder.Build(PolicyClis.ClaudeCode, "Read", default, "s", [], Root);

        Assert.Equal("read", input.Kind);
        Assert.Null(input.Details.Paths);
    }

    [Fact]
    public void Serialization_uses_the_source_generated_context_only()
    {
        var input = PolicyInputBuilder.Build(PolicyClis.ClaudeCode, "Bash", default, "s", [new PolicyFinding("D", "low")], Root);

        Assert.Equal(
            PolicyInputSerializer.Serialize(input),
            JsonSerializer.Serialize(input, PolicyInputJsonContext.Default.PolicyInput));
    }
}
