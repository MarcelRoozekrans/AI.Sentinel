namespace AI.Sentinel.ClaudeCode.SignIn;

/// <summary>Why a sign-in or a refresh failed.</summary>
internal enum SignInFailure
{
    /// <summary>The device code ran out before the developer approved it.</summary>
    Expired,

    /// <summary>The developer, or the provider's policy, refused.</summary>
    Denied,

    /// <summary>The provider no longer accepts the refresh token: a sign-in is needed.</summary>
    Rejected,

    /// <summary>The provider or the server could not be reached, or answered with an error. Trying again may work.</summary>
    Unavailable,

    /// <summary>An answer is not what the protocol says; nothing is trusted.</summary>
    Protocol,
}
