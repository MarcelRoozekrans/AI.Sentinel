namespace AI.Sentinel.ClaudeCode.Policy;

/// <summary>
/// Parses a POSIX style command line into simple commands joined by <c>|</c>, <c>&amp;&amp;</c>, <c>||</c>, <c>;</c> and
/// <c>&amp;</c>, with quoting, escapes and redirections. It does no expansion. Anything it cannot read with certainty gives
/// <see cref="ShellParse.Failed"/> instead of a guess: command and process substitution, subshells, here documents,
/// compound commands, locale and ANSI-C quoting, subscript assignments, brace expansion in the command name, an
/// unterminated quote. The corpus in <c>tests/AI.Sentinel.Tests/Corpus/shell-commands.json</c>
/// defines the behaviour, so another parser can be checked against it.
/// </summary>
internal static class ShellCommandParser
{
    private static readonly HashSet<string> ReservedWords = new(StringComparer.Ordinal)
    {
        "if", "then", "else", "elif", "fi", "for", "while", "until", "do", "done", "case", "esac", "in", "select",
        "function", "{", "}", "!", "[[", "]]", "coproc", "time",
    };

    public static ShellParse Parse(string commandLine)
    {
        ArgumentNullException.ThrowIfNull(commandLine);
        if (commandLine.Contains('\0', StringComparison.Ordinal))
        {
            return ShellParse.Failed;
        }

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
                assignments.Add(token.Text[..token.Text.IndexOf('=', StringComparison.Ordinal)].TrimEnd('+'));
            }
            else if (name is null)
            {
                if (token.Plain && ReservedWords.Contains(token.Text))
                {
                    return null;
                }

                if (IsSubscriptAssignment(token.Text) || IsBraceExpansion(token.Text))
                {
                    return null; // a[0]=x is an assignment and {a,b} expands into several words: neither is modelled
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

    // NAME[subscript]=value and NAME[subscript]+=value.
    private static bool IsSubscriptAssignment(string text)
    {
        var open = text.IndexOf('[', StringComparison.Ordinal);
        if (open <= 0 || char.IsAsciiDigit(text[0]))
        {
            return false;
        }

        for (var k = 0; k < open; k++)
        {
            if (!(char.IsAsciiLetterOrDigit(text[k]) || text[k] == '_'))
            {
                return false;
            }
        }

        return text.Contains("]=", StringComparison.Ordinal) || text.Contains("]+=", StringComparison.Ordinal);
    }

    private static bool IsBraceExpansion(string text) =>
        text.Contains('{', StringComparison.Ordinal)
        && (text.Contains(',', StringComparison.Ordinal) || text.Contains("..", StringComparison.Ordinal));
}
