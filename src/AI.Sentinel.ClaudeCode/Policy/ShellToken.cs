namespace AI.Sentinel.ClaudeCode.Policy;

/// <summary>A lexical token. <paramref name="Plain"/> is true for a word typed without quotes or escapes.</summary>
internal readonly record struct ShellToken(ShellTokenKind Kind, string Text, bool Plain, bool Assignment);
