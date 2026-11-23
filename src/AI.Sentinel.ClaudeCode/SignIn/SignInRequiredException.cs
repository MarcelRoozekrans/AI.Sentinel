namespace AI.Sentinel.ClaudeCode.SignIn;

/// <summary>A request to the server needs a token and the developer has to sign in first.</summary>
internal sealed class SignInRequiredException() : InvalidOperationException("sign-in is needed");
