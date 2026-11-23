namespace AI.Sentinel.Tests.ClaudeCode.Resident;

internal static class ResidentTestSupport
{
    public static string NewDir()
    {
        // Short, because a Unix socket path is limited to about 100 bytes.
        var dir = Path.Combine(Path.GetTempPath(), "sr-" + Guid.NewGuid().ToString("N")[..10]);
        return dir;
    }

    public static void Delete(string dir)
    {
        foreach (var d in new[] { dir, dir + ".private" })
        {
            try
            {
                Directory.Delete(d, recursive: true);
            }
            catch (IOException)
            {
                // Best effort.
            }
            catch (UnauthorizedAccessException)
            {
                // Best effort.
            }
        }
    }
}
