namespace AI.Sentinel.ClaudeCode.Resident;

/// <summary>The operations of the local channel.</summary>
internal static class ResidentOps
{
    public const string Ping = "ping";
    public const string Shutdown = "shutdown";

    /// <summary>Evaluates a policy folder for one input.</summary>
    public const string Evaluate = "evaluate";

    /// <summary>Hands the tokens of a sign-in to the process (#659). They stay in its memory.</summary>
    public const string SignIn = "sign_in";

    /// <summary>Asks whether the developer is signed in.</summary>
    public const string SignInStatus = "sign_in_status";
}
