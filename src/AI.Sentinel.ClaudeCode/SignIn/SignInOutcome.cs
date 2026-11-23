using AI.Sentinel.Profiles;

namespace AI.Sentinel.ClaudeCode.SignIn;

/// <summary>What a sign-in produced: the tokens, and the server keys the plugin now pins (#671).</summary>
internal sealed record SignInOutcome(TokenSet Tokens, string Organisation, PinnedProfileKeys Keys);
