namespace AI.Sentinel.ClaudeCode.Policy;

/// <summary>
/// Parses a POSIX style command line into simple commands joined by <c>|</c>, <c>&amp;&amp;</c>, <c>||</c>, <c>;</c> and
/// <c>&amp;</c>, with quoting, escapes and redirections. It does no expansion. Anything it cannot read with certainty gives
/// <see cref="ShellParse.Failed"/> instead of a guess: command and process substitution, subshells, here documents,
/// compound commands, an unterminated quote. The corpus in <c>tests/AI.Sentinel.Tests/Corpus/shell-commands.json</c>
/// defines the behaviour, so another parser can be checked against it.
/// </summary>
internal static class ShellCommandParser
{
    private static readonly HashSet<string> ReservedWords = new(StringComparer.Ordinal)
    {
        "if", "then", "else", "elif", "fi", "for", "while", "until", "do", "done", "case", "esac", "in", "select",
        "function", "{", "}", "!", "[[", "]]", "coproc",
    };

    public static ShellParse Parse(string commandLine)
    {
        ArgumentNullException.ThrowIfNull(commandLine);
        var tokens = ShellLexer.Lex(commandLine);
        return tokens is null ? ShellParse.Failed : Group(tokens);
    }

    private static ShellParse Group(List<ShellToken> tokens)
    {
        var commands = new List<ShellCommand>();
        string? joiner = null;
        var cursor = 0;
        while (cursor < tokens.Count)
        {
            var command = ReadCommand(tokens, ref cursor, joiner);
            if (command is null)
            {
                return ShellParse.Failed;
            }

            commands.Add(command);
            if (cursor >= tokens.Count)
            {
                break;
            }

            joiner = tokens[cursor].Text;
            cursor++;
            if (cursor >= tokens.Count && joiner is not (";" or "&"))
            {
                return ShellParse.Failed; // a trailing && || or | has no right side
            }
        }

        return new ShellParse(false, commands);
    }

    private static ShellCommand? ReadCommand(List<ShellToken> tokens, ref int cursor, string? joiner)
    {
        string? name = null;
        var args = new List<string>();
        var assignments = new List<string>();
        var redirects = new List<ShellRedirect>();
        for (; cursor < tokens.Count && tokens[cursor].Kind != ShellTokenKind.Operator; cursor++)
        {
            var token = tokens[cursor];
            if (token.Kind == ShellTokenKind.Redirect)
            {
                if (cursor + 1 >= tokens.Count || tokens[cursor + 1].Kind != ShellTokenKind.Word)
                {
                    return null;
                }

                cursor++;
                redirects.Add(new ShellRedirect(token.Text, tokens[cursor].Text));
            }
            else if (name is null && token.Assignment)
            {
                assignments.Add(token.Text[..token.Text.IndexOf('=', StringComparison.Ordinal)]);
            }
            else if (name is null)
            {
                if (token.Plain && ReservedWords.Contains(token.Text))
                {
                    return null;
                }

                name = token.Text;
            }
            else
            {
                args.Add(token.Text);
            }
        }

        if (name is null && assignments.Count == 0 && redirects.Count == 0)
        {
            return null; // empty command next to an operator
        }

        return new ShellCommand(joiner, name ?? "", args, assignments, redirects);
    }
}
