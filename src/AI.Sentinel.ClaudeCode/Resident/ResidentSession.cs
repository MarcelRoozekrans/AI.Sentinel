using AI.Sentinel.ClaudeCode.Policy;

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

    /// <summary>The source a pause is named by.</summary>
    public const string PauseSource = "pause";

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

    /// <summary>
    /// <paramref name="output"/> with the pause state applied: a call of a paused session is denied, whatever else was decided, and
    /// <paramref name="output"/> is returned as it is for any other session. The pause is read from the state folder, so this needs no
    /// network and no running process. A state folder that cannot be used throws, and the hook blocks the call.
    /// </summary>
    /// <param name="output">What the other checks decided.</param>
    /// <param name="sessionId">The session of the call.</param>
    /// <param name="now">The current time.</param>
    public HookOutput ApplyPause(HookOutput output, string sessionId, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(output);
        if (string.IsNullOrEmpty(sessionId) || ResidentState.Open(Settings).FindPause(sessionId, now) is not { } pause)
        {
            return output;
        }

        var reason = string.IsNullOrWhiteSpace(pause.Reason)
            ? "AI.Sentinel is paused for this session."
            : $"AI.Sentinel is paused for this session: {pause.Reason}";
        var paused = new OutcomeDecision(DecisionOutcome.Deny, reason, [PauseSource]);
        var existing = output.Outcome ?? OutcomeDecision.FromHook(output.Decision, output.Reason, LocalPolicy.ChecksSource);
        return OutcomeDecision.Strictest([existing, paused]).ToHookOutput(canAsk: true);
    }
}
