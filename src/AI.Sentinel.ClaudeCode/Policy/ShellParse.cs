namespace AI.Sentinel.ClaudeCode.Policy;

/// <summary>The parse of a command line. When <see cref="Unparseable"/>, <see cref="Commands"/> is empty and the policy outcome is ask.</summary>
internal sealed record ShellParse(bool Unparseable, IReadOnlyList<ShellCommand> Commands)
{
    public static ShellParse Failed { get; } = new(true, []);
}
