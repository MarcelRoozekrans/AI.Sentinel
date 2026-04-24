using Xunit;
using AI.Sentinel.Mcp.Cli;

namespace AI.Sentinel.Tests.Mcp;

public class McpCliTests
{
    [Fact]
    public async Task NoArgs_ExitsOneWithUsage()
    {
        var stdin = new StringReader("");
        var stdout = new StringWriter();
        var stderr = new StringWriter();

        var exit = await Program.RunAsync(Array.Empty<string>(), stdin, stdout, stderr);

        Assert.Equal(1, exit);
        Assert.Contains("Usage", stderr.ToString(), StringComparison.Ordinal);
        Assert.Contains("--target", stderr.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task UnknownSubcommand_ExitsOneWithUsage()
    {
        var stdin = new StringReader("");
        var stdout = new StringWriter();
        var stderr = new StringWriter();

        var exit = await Program.RunAsync(new[] { "foo" }, stdin, stdout, stderr);

        Assert.Equal(1, exit);
        Assert.Contains("Usage", stderr.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task ProxyWithoutTarget_ExitsOneWithUsage()
    {
        var stdin = new StringReader("");
        var stdout = new StringWriter();
        var stderr = new StringWriter();

        var exit = await Program.RunAsync(new[] { "proxy" }, stdin, stdout, stderr);

        Assert.Equal(1, exit);
        Assert.Contains("--target", stderr.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task ProxyWithMissingTargetBinary_ExitsTwo()
    {
        var stdin = new StringReader("");
        var stdout = new StringWriter();
        var stderr = new StringWriter();

        // A binary name that definitely doesn't exist on PATH.
        var exit = await Program.RunAsync(
            new[] { "proxy", "--target", "this-binary-does-not-exist-xyz-abc-42" },
            stdin, stdout, stderr);

        Assert.Equal(2, exit);
        Assert.Contains("target process failed", stderr.ToString(), StringComparison.Ordinal);
    }
}
