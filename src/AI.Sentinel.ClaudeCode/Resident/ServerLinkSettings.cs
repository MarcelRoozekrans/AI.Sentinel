namespace AI.Sentinel.ClaudeCode.Resident;

/// <summary>How the resident process reaches the server: where it is, how it waits, and the handler of the HTTP client, which a test replaces.</summary>
/// <param name="ServerUrl">The server.</param>
/// <param name="Timing">The waits.</param>
/// <param name="Handler">The inner HTTP handler; the platform default when <see langword="null"/>.</param>
internal sealed record ServerLinkSettings(Uri ServerUrl, ServerLinkTiming Timing, HttpMessageHandler? Handler = null);
