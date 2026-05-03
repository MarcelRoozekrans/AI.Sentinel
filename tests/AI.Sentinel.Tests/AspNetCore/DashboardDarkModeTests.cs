using System.Reflection;
using Xunit;

namespace AI.Sentinel.Tests.AspNetCore;

public class DashboardDarkModeTests
{
    [Fact]
    public void SentinelCss_ContainsPrefersColorSchemeLightBlock()
    {
        // Walk up from the test assembly directory until we find the .git folder so the path
        // math is robust across both net8.0 and net10.0 test outputs (and any future TFM bumps).
        var dir = new DirectoryInfo(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location)!);
        while (dir is not null && !Directory.Exists(Path.Combine(dir.FullName, ".git")))
            dir = dir.Parent;
        Assert.NotNull(dir);

        var cssPath = Path.Combine(dir!.FullName, "src", "AI.Sentinel.AspNetCore", "wwwroot", "sentinel.css");
        Assert.True(File.Exists(cssPath), $"Expected to find sentinel.css at {cssPath}");
        var css = File.ReadAllText(cssPath);
        Assert.Contains("@media (prefers-color-scheme: light)", css, StringComparison.Ordinal);
        Assert.Contains("--bg:", css, StringComparison.Ordinal);
    }
}
