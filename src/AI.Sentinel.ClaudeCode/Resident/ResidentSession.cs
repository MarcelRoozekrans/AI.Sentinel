namespace AI.Sentinel.ClaudeCode.Resident;

/// <summary>
/// The resident process as one hook call sees it: the settings and a client, with the process started when none runs. Opening one
/// never throws and never waits for the process: a hook that finds none starts it and evaluates that call in-process.
/// </summary>
internal sealed class ResidentSession
{
    private ResidentSession(ResidentSettings settings, ResidentStart start)
    {
        Settings = settings;
        Client = new ResidentClient(settings);
        Start = start;
    }

    public ResidentSettings Settings { get; }

    public ResidentClient Client { get; }

    /// <summary>What opening found: a process already running, one just started, or none and none could be started.</summary>
    public ResidentStart Start { get; }

    /// <summary>The session for the hook's settings, or <see langword="null"/> when the resident process is not turned on, in
    /// which case nothing is started and nothing changes.</summary>
    /// <param name="env">The <c>SENTINEL_HOOK_</c> settings.</param>
    /// <param name="start">Starts the process; <see cref="ResidentLauncher.StartDetached"/> with <see cref="ResidentLaunch.ForThisHook"/>
    /// when <see langword="null"/>.</param>
    public static ResidentSession? Open(IReadOnlyDictionary<string, string?> env, Func<ResidentLaunch, bool>? start = null)
    {
        if (ResidentSettings.FromEnvironment(env) is not { } settings)
        {
            return null;
        }

        return new ResidentSession(settings, ResidentLauncher.EnsureStarted(settings, ResidentLaunch.ForThisHook(), start));
    }
}
