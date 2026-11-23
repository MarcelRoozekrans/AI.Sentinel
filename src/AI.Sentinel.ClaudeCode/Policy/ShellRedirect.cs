namespace AI.Sentinel.ClaudeCode.Policy;

/// <summary>One redirection of a command, such as <c>2&gt;</c> with its target word.</summary>
internal sealed record ShellRedirect(string Op, string Target);
