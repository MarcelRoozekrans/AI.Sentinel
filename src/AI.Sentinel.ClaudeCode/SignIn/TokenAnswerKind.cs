namespace AI.Sentinel.ClaudeCode.SignIn;

internal enum TokenAnswerKind
{
    Token,
    SignInRequired,

    /// <summary>The provider could not be reached; the session stays signed in and the caller tries again later.</summary>
    Unavailable,
}
