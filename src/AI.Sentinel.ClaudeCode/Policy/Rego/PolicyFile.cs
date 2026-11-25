namespace AI.Sentinel.ClaudeCode.Policy.Rego;

/// <summary>One Rego source file of a policy folder: its path below the folder with forward slashes, and its text.</summary>
internal sealed record PolicyFile(string Path, string Text);
