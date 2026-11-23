namespace AI.Sentinel.ClaudeCode.Policy.Rego;

/// <summary>Writes the files of a <see cref="PolicySources"/> to a folder for a compiler that reads a folder.</summary>
internal static class SourceFolder
{
    public static void Write(PolicySources sources, string root)
    {
        foreach (var file in sources.Files)
        {
            var path = Path.Combine(root, file.Path);
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, file.Text);
        }
    }
}
