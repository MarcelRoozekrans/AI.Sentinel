namespace AI.Sentinel.ClaudeCode.SignIn;

/// <summary>The answer to a request for the access token.</summary>
internal readonly record struct TokenAnswer(TokenAnswerKind Kind, string? AccessToken)
{
    public override string ToString() => $"TokenAnswer {Kind}";
}
