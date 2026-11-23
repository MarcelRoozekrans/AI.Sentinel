namespace AI.Sentinel.ClaudeCode.Policy;

/// <summary>Details of a shell call.</summary>
/// <param name="Unparseable">True when the command line could not be parsed. The outcome for it is ask, built in #670.</param>
/// <param name="Commands">The parsed commands. Empty when unparseable.</param>
internal sealed record ShellDetails(bool Unparseable, IReadOnlyList<ShellCommand> Commands);
