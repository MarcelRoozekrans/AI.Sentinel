namespace AI.Sentinel.ClaudeCode.SignIn;

/// <summary>A sign-in or refresh failed. The message never holds a token.</summary>
internal sealed class SignInException(SignInFailure kind, string message) : Exception(message)
{
    public SignInFailure Kind { get; } = kind;
}
