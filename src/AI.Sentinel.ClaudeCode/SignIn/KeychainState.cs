namespace AI.Sentinel.ClaudeCode.SignIn;

/// <summary>What the keychain holds after a sign-in was kept.</summary>
internal enum KeychainState
{
    /// <summary>The refresh token of this sign-in.</summary>
    Kept,

    /// <summary>No refresh token: there is no keychain, or the sign-in has none to keep, and no earlier one remains.</summary>
    MemoryOnly,

    /// <summary>The keychain did not take this sign-in and could not remove the token of an earlier one, so a restart would resume it.</summary>
    EarlierRemains,
}
