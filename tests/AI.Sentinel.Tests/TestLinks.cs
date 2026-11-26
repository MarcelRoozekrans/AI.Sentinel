using Xunit;

namespace AI.Sentinel.Tests;

/// <summary>Creates the symbolic links a test needs. On Windows that takes Developer Mode or an elevated shell; without either
/// the test is skipped, with the reason, instead of failing before it reaches the code it is about.</summary>
internal static class TestLinks
{
    public static void Directory(string link, string target) => Create(() => System.IO.Directory.CreateSymbolicLink(link, target));

    public static void File(string link, string target) => Create(() => System.IO.File.CreateSymbolicLink(link, target));

    private static void Create(Action create)
    {
        try
        {
            create();
        }
        catch (Exception e) when (OperatingSystem.IsWindows() && e is UnauthorizedAccessException or IOException)
        {
            Assert.Skip("creating a symbolic link on Windows needs Developer Mode or an elevated shell");
        }
    }
}
