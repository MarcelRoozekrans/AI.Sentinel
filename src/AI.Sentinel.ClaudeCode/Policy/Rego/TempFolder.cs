namespace AI.Sentinel.ClaudeCode.Policy.Rego;

/// <summary>A folder under the system temp directory that is removed when disposed. It only ever holds Rego sources.</summary>
internal sealed class TempFolder : IDisposable
{
    public TempFolder() => Path = Directory.CreateTempSubdirectory("sentinel-rego-").FullName;

    public string Path { get; }

    public void Dispose()
    {
        try
        {
            Directory.Delete(Path, recursive: true);
        }
        catch (IOException)
        {
            // A leftover temporary folder of Rego sources harms nothing.
        }
        catch (UnauthorizedAccessException)
        {
            // As above.
        }
    }
}
