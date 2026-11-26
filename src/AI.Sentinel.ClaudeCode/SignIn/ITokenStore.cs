namespace AI.Sentinel.ClaudeCode.SignIn;

/// <summary>
/// Where the refresh token is kept across a restart of the resident process: the keychain of the operating system. An implementation
/// holds the secret in the keychain only, never in a file of its own. Every call may fail, because the keychain may be missing, locked
/// or full; a failure is a false or a null, never an exception, and never prints the secret.
/// </summary>
internal interface ITokenStore
{
    /// <summary>Names the keychain for the log, for example <c>Windows Credential Manager</c>.</summary>
    string Name { get; }

    /// <summary>Keeps <paramref name="secret"/>, replacing an earlier one. False when the keychain did not take it.</summary>
    bool Save(string secret);

    /// <summary>The kept secret, or <see langword="null"/> when there is none or the keychain cannot be read.</summary>
    string? Load();

    /// <summary>Removes the kept secret. False when the keychain failed while it may still hold one; a secret that is not there is not a
    /// failure, and neither is a keychain this store cannot reach at all, since <see cref="Load"/> cannot read a secret from it either.</summary>
    bool Delete();
}
