namespace AI.Sentinel.Tests.Helpers;

/// <summary>Sets environment variables for a test and restores the previous values on dispose.</summary>
public sealed class EnvironmentScope : IDisposable
{
    private readonly List<(string Name, string? Previous)> _previous = [];

    public EnvironmentScope(params (string Name, string? Value)[] variables)
    {
        foreach (var (name, value) in variables)
        {
            _previous.Add((name, Environment.GetEnvironmentVariable(name)));
            Environment.SetEnvironmentVariable(name, value);
        }
    }

    /// <summary>The SENTINEL_REVIEW_* settings that point a host at <paramref name="server"/>.</summary>
    public static EnvironmentScope Review(ReviewStubServer server, string? timeoutMs = null, string? maxPerScan = null) => new(
        ("SENTINEL_REVIEW_ENDPOINT", server.Endpoint),
        ("SENTINEL_REVIEW_MODEL", "stub-model"),
        ("SENTINEL_REVIEW_TIMEOUT_MS", timeoutMs),
        ("SENTINEL_REVIEW_MAX_PER_SCAN", maxPerScan));

    public void Dispose()
    {
        foreach (var (name, previous) in _previous)
        {
            Environment.SetEnvironmentVariable(name, previous);
        }
    }
}
