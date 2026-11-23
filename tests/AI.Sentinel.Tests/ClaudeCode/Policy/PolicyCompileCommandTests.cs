using System.Runtime.InteropServices;
using AI.Sentinel.ClaudeCode.Policy.Rego;
using Xunit;

namespace AI.Sentinel.Tests.ClaudeCode.Policy;

/// <summary>The interop compiler is in every build of the hook library; whether a hook can use it is decided at run time by
/// the platform, and the child command and the hook's compiler say why when it cannot.</summary>
public class PolicyCompileCommandTests
{
    [Theory]
    [InlineData("linux-x64", Architecture.X64, true, false)]
    [InlineData("win-x64", Architecture.X64, false, true)]
    [InlineData("ubuntu.24.04-x64", Architecture.X64, true, false)]
    public void The_interop_compiler_runs_on_x64_linux_with_glibc_and_on_x64_windows(string rid, Architecture architecture, bool linux, bool windows)
    {
        Assert.Null(InteropRegoCompiler.Unavailable(rid, architecture, linux, windows));
    }

    [Theory]
    [InlineData("linux-musl-x64", Architecture.X64, true, false)]
    [InlineData("linux-arm64", Architecture.Arm64, true, false)]
    [InlineData("osx-arm64", Architecture.Arm64, false, false)]
    [InlineData("osx-x64", Architecture.X64, false, false)]
    [InlineData("win-arm64", Architecture.Arm64, false, true)]
    public void Elsewhere_the_interop_compiler_is_unavailable_and_names_the_runtime(string rid, Architecture architecture, bool linux, bool windows)
    {
        var reason = InteropRegoCompiler.Unavailable(rid, architecture, linux, windows);

        Assert.Equal($"the OpaDotNet interop compiler has no native library for {rid}", reason);
    }

    [Theory]
    [InlineData]
    [InlineData("--compile-policy")]
    [InlineData("--compile-policy", "src")]
    [InlineData("--compile-policy", "src", "out", "--restricted")]
    [InlineData("--compile-policy", "src", "out", "--unrestricted", "extra")]
    [InlineData("--other", "src", "out")]
    public void Other_arguments_print_the_usage(params string[] args)
    {
        using var stderr = new StringWriter();

        Assert.Equal(PolicyCompileCommand.BadUsage, PolicyCompileCommand.Run(args, stderr, unavailable: null));
        Assert.StartsWith("usage: --compile-policy <source-folder> <output> [--unrestricted]", stderr.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void Without_the_interop_library_the_command_says_why_and_writes_nothing()
    {
        var output = Path.Combine(Path.GetTempPath(), "sentinel-compile-" + Guid.NewGuid().ToString("N"));
        using var stderr = new StringWriter();

        var exit = PolicyCompileCommand.Run(["--compile-policy", "src", output], stderr, unavailable: "no library here");

        Assert.Equal(PolicyCompileCommand.NoCompiler, exit);
        Assert.Equal("no library here", stderr.ToString().Trim());
        Assert.False(File.Exists(output));
    }

    [Fact]
    public void A_hook_on_the_dotnet_host_starts_the_host_with_its_assembly_and_a_native_hook_starts_itself()
    {
        var onHost = ChildProcessRegoCompiler.ForThisHook("/usr/share/dotnet/dotnet", "/tools/sentinel-hook.dll", unavailable: null);
        var native = ChildProcessRegoCompiler.ForThisHook("/tools/sentinel-hook", "/tools/sentinel-hook", unavailable: null);

        Assert.Equal("/usr/share/dotnet/dotnet", onHost.Command.FileName);
        Assert.Equal(["/tools/sentinel-hook.dll"], onHost.Command.LeadingArgs);
        Assert.Equal("/tools/sentinel-hook", native.Command.FileName);
        Assert.Empty(native.Command.LeadingArgs);
        Assert.Null(native.Unavailable());
    }

    [Fact]
    public void A_hook_whose_executable_is_unknown_cannot_start_the_compiler_and_says_so()
    {
        Assert.Equal("the path of the hook executable is unknown", ChildProcessRegoCompiler.ForThisHook(null, "x", unavailable: null).Unavailable());
        Assert.Equal("no library here", ChildProcessRegoCompiler.ForThisHook(string.Empty, "x", "no library here").Unavailable());
    }
}
