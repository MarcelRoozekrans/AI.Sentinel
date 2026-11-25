namespace AI.Sentinel.ClaudeCode.Policy.Rego;

/// <summary>Writes the files of a <see cref="PolicySources"/> to a folder for a compiler that reads a folder.</summary>
internal static class SourceFolder
{
    public static void Write(PolicySources sources, string root)
    {
        ArgumentNullException.ThrowIfNull(sources);
        var staging = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));
        var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        foreach (var file in sources.Files)
        {
            var path = Path.GetFullPath(Path.Combine(staging, file.Path));
            if (!path.StartsWith(staging + Path.DirectorySeparatorChar, comparison))
            {
                throw new InvalidDataException($"{file.Path}: resolves outside the staging folder");
            }

            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, file.Text);
        }
    }
}
