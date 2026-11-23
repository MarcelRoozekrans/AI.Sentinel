namespace AI.Sentinel.ClaudeCode.Policy;

/// <summary>One simple command of a command line.</summary>
/// <param name="Operator">The operator that joins it to the previous command: <c>|</c>, <c>&amp;&amp;</c>, <c>||</c>,
/// <c>;</c> or <c>&amp;</c>. Null for the first command.</param>
/// <param name="Name">The command word. Empty when the command is only variable assignments.</param>
/// <param name="Args">Arguments, quotes and escapes removed, no expansion done.</param>
/// <param name="Assignments">Names of the variables assigned before the command. Their values are not kept.</param>
/// <param name="Redirects">Redirections in the order they appear.</param>
internal sealed record ShellCommand(
    string? Operator,
    string Name,
    IReadOnlyList<string> Args,
    IReadOnlyList<string> Assignments,
    IReadOnlyList<ShellRedirect> Redirects);
