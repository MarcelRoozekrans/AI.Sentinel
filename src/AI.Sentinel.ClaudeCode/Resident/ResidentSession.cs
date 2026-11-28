using AI.Sentinel.ClaudeCode.Policy;

namespace AI.Sentinel.ClaudeCode.Resident;

/// <summary>
/// The resident process as one hook call sees it: the settings and a client, with the process started when none runs. Opening one
/// never throws and never waits for the process: a hook that finds none starts it and evaluates that call in-process. Every exchange of
/// the call shares one <see cref="Budget"/>.
/// </summary>
internal sealed class ResidentSession : IResidentProfiles
{
    private ResidentSession(ResidentSettings settings, ResidentStart start)
    {
        Settings = settings;
        Client = new ResidentClient(settings);
        Start = start;
        Budget = new ResidentBudget(settings.Budget);
    }

    /// <summary>The source a pause is named by.</summary>
    public const string PauseSource = "pause";

    public ResidentSettings Settings { get; }

    public ResidentClient Client { get; }

    /// <summary>What opening found: a process already running, one just started, or none and none could be started.</summary>
    public ResidentStart Start { get; }

    /// <summary>The time this hook call may wait for the process, over all its exchanges.</summary>
    public ResidentBudget Budget { get; }

    /// <summary>A state folder that is not private is not used: the socket, the node map and the profiles in it could be another user's.
    /// The hooks fail closed, so this throws and the caller blocks the call.</summary>
    /// <exception cref="UnauthorizedAccessException">The state folder and its private sibling are open to other users.</exception>
    public void ThrowIfUnusable()
    {
        if (Start == ResidentStart.Unusable)
        {
            throw new UnauthorizedAccessException(
                $"the resident state folder '{Settings.StateDirectory}' and its .private sibling are open to other users, so the hook cannot use them; make the folder private to you");
        }
    }

    /// <summary>The warm module of a profile, asked only of a process that already ran: a hook that started one, or failed to, does not
    /// wait for it and decides this call in-process.</summary>
    public Policy.Rego.RegoDecision? Evaluate(string repository, string moduleHash, string inputJson) =>
        Start != ResidentStart.AlreadyRunning ? null : Budget.Spend(left => Client.EvaluateProfile(repository, moduleHash, inputJson, left));

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

        var paused = new OutcomeDecision(DecisionOutcome.Deny, pause.DenyReason(), [PauseSource]);
        var existing = output.Outcome ?? OutcomeDecision.FromHook(output.Decision, output.Reason, LocalPolicy.ChecksSource);
        return OutcomeDecision.Strictest([existing, paused]).ToHookOutput(canAsk: true);
    }
}
