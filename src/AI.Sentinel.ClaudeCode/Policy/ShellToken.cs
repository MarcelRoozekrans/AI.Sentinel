namespace AI.Sentinel.ClaudeCode.Policy;

/// <summary>A lexical token. <paramref name="Plain"/> is true for a word typed without quotes or escapes.
/// <paramref name="Expands"/> is true when the shell would expand the word before use: an active <c>$</c>, an unquoted glob
/// character or a leading unquoted <c>~</c>. The text then is not what the shell runs.</summary>
internal readonly record struct ShellToken(ShellTokenKind Kind, string Text, bool Plain, bool Assignment, bool Expands = false);
