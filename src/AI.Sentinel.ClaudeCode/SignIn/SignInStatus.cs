namespace AI.Sentinel.ClaudeCode.SignIn;

/// <summary>Whether the developer is signed in.</summary>
internal enum SignInStatus
{
    /// <summary>No token is held, or the one held can no longer be renewed: the developer signs in again.</summary>
    SignInNeeded,

    /// <summary>A token is held, or can be renewed.</summary>
    SignedIn,
}
