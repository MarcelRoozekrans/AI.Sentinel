using AI.Sentinel.ClaudeCode.Resident;
using AI.Sentinel.ClaudeCode.SignIn;
using AI.Sentinel.Sqlite.Local;

namespace AI.Sentinel.ClaudeCode.Events;

/// <summary>Builds the forwarder of the resident process from its settings (#661). Off unless the server is configured and the developer
/// can sign in to it: with none of the settings set nothing is sent, as before.</summary>
internal static class EventForwarding
{
    /// <summary>The path of the ingest endpoint on the server.</summary>
    public const string IngestPath = "/ai-sentinel/events/ingest";

    /// <summary>How often the resident process looks for entries to send.</summary>
    public static readonly TimeSpan DefaultInterval = TimeSpan.FromSeconds(10);

    /// <summary>The forwarder, or <see langword="null"/> when no server is configured, there is no sign-in, or the local audit is off.</summary>
    /// <param name="env">The <c>SENTINEL_HOOK_</c> settings.</param>
    /// <param name="settings">The settings of the resident process, which name the state folder.</param>
    /// <param name="tokens">The sign-in session, whose token goes to the server only.</param>
    /// <param name="inner">The handler under the token handler; a socket handler when <see langword="null"/>.</param>
    /// <param name="log">Where problems go.</param>
    public static EventForwarder? Open(
        IReadOnlyDictionary<string, string?> env, ResidentSettings settings, TokenSession? tokens, HttpMessageHandler? inner, TextWriter log)
    {
        ArgumentNullException.ThrowIfNull(env);
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(log);
        if (tokens is null || SignInSettings.FromEnvironment(env, out _) is not { } signIn)
        {
            return null;
        }

        var problems = new List<string>();
        var audit = LocalAudit.ReadSettings(env, "SENTINEL_HOOK_", LocalAudit.DefaultDatabasePath(), problems);
        if (audit.DatabasePath is not { } database)
        {
            return null;
        }

        var state = ResidentState.Open(settings);
        var logging = new DetailedLoggingSwitch(state.Directory, state.ReadPinnedKeys, TimeProvider.System);
        var http = new HttpClient(new BearerTokenHandler(tokens, inner ?? new SocketsHttpHandler(), signIn.ServerUrl)) { Timeout = TimeSpan.FromSeconds(15) };
        var endpoint = new Uri(signIn.ServerUrl.ToString().TrimEnd('/') + IngestPath);
        return new EventForwarder(
            new SqliteAuditSource(database), new EventCursor(state.Directory), http, endpoint,
            () => state.ReadPinnedKeys()?.Organisation, logging.IsOn, line => log.WriteLine(line));
    }
}
