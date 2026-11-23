using System.Text;

namespace AI.Sentinel.ClaudeCode.Policy;

/// <summary>Splits a command line into words, operators and redirections. Returns null for anything it cannot read with certainty.</summary>
internal sealed class ShellLexer
{
    private readonly string _s;
    private readonly List<ShellToken> _tokens = [];
    private readonly StringBuilder _word = new();
    private int _i;
    private bool _inWord;
    private bool _plain = true;
    private int _plainEnd = -1;

    private ShellLexer(string s) => _s = s;

    public static List<ShellToken>? Lex(string commandLine) => new ShellLexer(commandLine).Result();

    private List<ShellToken>? Result() => Run() ? _tokens : null;

    private bool Run()
    {
        while (_i < _s.Length)
        {
            if (!Step())
            {
                return false;
            }
        }

        Flush();
        return true;
    }

    private bool Step()
    {
        var c = _s[_i];
        switch (c)
        {
            case ' ' or '\t' or '\r':
                Flush();
                _i++;
                return true;
            case '\n':
                Flush();
                if (_tokens.Count > 0 && _tokens[^1].Kind != ShellTokenKind.Operator)
                {
                    AddOperator(";");
                }

                _i++;
                return true;
            case '\\':
                return Backslash();
            case '\'':
                return SingleQuoted();
            case '"':
                MarkQuoted();
                return DoubleQuoted();
            case '`' or '(' or ')':
                return false;
            case '$':
                if (_i + 1 < _s.Length && _s[_i + 1] is '(' or '\'')
                {
                    return false;
                }

                Append(c);
                return true;
            case '#' when !_inWord:
                while (_i < _s.Length && _s[_i] != '\n')
                {
                    _i++;
                }

                return true;
            case ';':
                return Operator(";");
            case '|':
                return Operator(Peek(1) == '|' ? "||" : "|");
            case '&':
                return Ampersand();
            case '<' or '>':
                return Redirect();
            default:
                Append(c);
                return true;
        }
    }

    private char Peek(int offset) => _i + offset < _s.Length ? _s[_i + offset] : '\0';

    private void Append(char c)
    {
        _inWord = true;
        _word.Append(c);
        _i++;
    }

    private bool Operator(string op)
    {
        Flush();
        AddOperator(op);
        _i += op.Length;
        return true;
    }

    private bool Ampersand()
    {
        Flush();
        if (Peek(1) == '>')
        {
            var redirect = Peek(2) == '>' ? "&>>" : "&>";
            _tokens.Add(new ShellToken(ShellTokenKind.Redirect, redirect, true, false));
            _i += redirect.Length;
            return true;
        }

        AddOperator(Peek(1) == '&' ? "&&" : "&");
        _i += _tokens[^1].Text.Length;
        return true;
    }

    private bool Backslash()
    {
        if (_i + 1 >= _s.Length)
        {
            return false;
        }

        if (_s[_i + 1] == '\n')
        {
            _i += 2;
            return true;
        }

        MarkQuoted();
        _word.Append(_s[_i + 1]);
        _i += 2;
        return true;
    }

    private bool SingleQuoted()
    {
        var end = _s.IndexOf('\'', _i + 1);
        if (end < 0)
        {
            return false;
        }

        MarkQuoted();
        _word.Append(_s, _i + 1, end - _i - 1);
        _i = end + 1;
        return true;
    }

    private bool DoubleQuoted()
    {
        _i++;
        while (_i < _s.Length)
        {
            var c = _s[_i];
            if (c == '"')
            {
                _i++;
                return true;
            }

            if (c == '`' || (c == '$' && Peek(1) == '('))
            {
                return false;
            }

            if (c == '\\' && _i + 1 < _s.Length)
            {
                var n = _s[_i + 1];
                if (n == '\n')
                {
                    _i += 2;
                    continue;
                }

                if (n is '"' or '\\' or '$' or '`')
                {
                    _word.Append(n);
                    _i += 2;
                    continue;
                }
            }

            _word.Append(c);
            _i++;
        }

        return false;
    }

    private bool Redirect()
    {
        var fd = "";
        if (_inWord && _plain && IsDigits())
        {
            fd = _word.ToString();
            _word.Clear();
            _inWord = false;
        }
        else
        {
            Flush();
        }

        var c = _s[_i];
        var next = Peek(1);
        if (next == '(' || (c == '<' && next is '<' or '>'))
        {
            return false; // process substitution, here document, here string
        }

        string op;
        if (next == c || (c == '>' && next is '|' or '&') || (c == '<' && next == '&'))
        {
            op = new string([c, next]);
            _i += 2;
        }
        else
        {
            op = c.ToString();
            _i++;
        }

        _tokens.Add(new ShellToken(ShellTokenKind.Redirect, fd + op, true, false));
        return true;
    }

    private bool IsDigits()
    {
        if (_word.Length == 0)
        {
            return false;
        }

        for (var k = 0; k < _word.Length; k++)
        {
            if (_word[k] is < '0' or > '9')
            {
                return false;
            }
        }

        return true;
    }

    private void AddOperator(string op) => _tokens.Add(new ShellToken(ShellTokenKind.Operator, op, true, false));

    private void MarkQuoted()
    {
        if (_plain)
        {
            _plain = false;
            _plainEnd = _word.Length;
        }

        _inWord = true;
    }

    private void Flush()
    {
        if (!_inWord)
        {
            return;
        }

        var text = _word.ToString();
        _tokens.Add(new ShellToken(ShellTokenKind.Word, text, _plain, IsAssignment(text, _plainEnd)));
        _word.Clear();
        _inWord = false;
        _plain = true;
        _plainEnd = -1;
    }

    // NAME=value where NAME is a plain identifier typed without quotes or escapes.
    private static bool IsAssignment(string text, int plainEnd)
    {
        var eq = text.IndexOf('=', StringComparison.Ordinal);
        if (eq <= 0 || (plainEnd >= 0 && plainEnd <= eq) || char.IsAsciiDigit(text[0]))
        {
            return false;
        }

        for (var k = 0; k < eq; k++)
        {
            if (!(char.IsAsciiLetterOrDigit(text[k]) || text[k] == '_'))
            {
                return false;
            }
        }

        return true;
    }
}
