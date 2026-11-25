namespace AI.Sentinel.ClaudeCode.Resident;

/// <summary>The program and arguments that start the resident process.</summary>
/// <param name="FileName">The program.</param>
/// <param name="Arguments">Its arguments; the last one is <see cref="ResidentCommand.Verb"/>.</param>
internal sealed record ResidentLaunch(string FileName, IReadOnlyList<string> Arguments)
{
    /// <summary>The running hook started again with the resident verb, as <c>dotnet &lt;assembly&gt;</c> when it runs on the
    /// <c>dotnet</c> host. The resident process is part of the hook binary, so no new download is needed.</summary>
    public static ResidentLaunch ForThisHook()
    {
        var process = Environment.ProcessPath;
        if (string.IsNullOrEmpty(process))
        {
            return new ResidentLaunch("sentinel-hook", [ResidentCommand.Verb]);
        }

        return Path.GetFileNameWithoutExtension(process).Equals("dotnet", StringComparison.OrdinalIgnoreCase)
            ? new ResidentLaunch(process, [Environment.GetCommandLineArgs()[0], ResidentCommand.Verb])
            : new ResidentLaunch(process, [ResidentCommand.Verb]);
    }
}
