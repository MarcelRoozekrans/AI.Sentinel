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
    private bool _expands;
    private int _bracket = -1;

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
            case ' ' or '\t':
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
                if (Peek(1) is '(' or '\'' or '"' or '[')
                {
                    return false; // $[1+2] is the legacy arithmetic expansion of Bash
                }

                if (Peek(1) == '{')
                {
                    return BracedExpansion();
                }

                NoteDollar();
                return Append1(c);
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
                NoteExpansion(c);
                Append(c);
                return true;
        }
    }

    // An unquoted *, ? or a [..] pair globs, and a ~ at the start of a word is a tilde expansion.
    private void NoteExpansion(char c)
    {
        if (c is '*' or '?' || (c == '~' && !_inWord))
        {
            _expands = true;
        }
        else if (c == '[' && _bracket < 0)
        {
            _bracket = _word.Length;
        }
        else if (c == ']' && _bracket >= 0 && _word.Length > _bracket + 1)
        {
            _expands = true;
        }
    }

    // A $ followed by a name, a digit or a special parameter expands.
    private void NoteDollar()
    {
        var n = Peek(1);
        if (char.IsAsciiLetterOrDigit(n) || n is '_' or '@' or '*' or '#' or '?' or '-' or '$' or '!')
        {
            _expands = true;
        }
    }

    // Index of the offset-th character after the current one, with backslash-newline pairs skipped as Bash removes them.
    private int Ahead(int offset)
    {
        var j = _i;
        for (var k = 0; k < offset; k++)
        {
            j++;
            while (j + 1 < _s.Length && _s[j] == '\\' && _s[j + 1] == '\n')
            {
                j += 2;
            }
        }

        return j;
    }

    private char Peek(int offset)
    {
        var j = Ahead(offset);
        return j < _s.Length ? _s[j] : '\0';
    }

    private bool Append1(char c)
    {
        Append(c);
        return true;
    }

    // ${...} stays one word. Only a plain body is read: anything that could nest, quote or run code inside it (including <( and >( process substitution) is left unparsed.
    private bool BracedExpansion()
    {
        var end = _s.IndexOf('}', _i + 2);
        if (end < 0)
        {
            return false;
        }

        // Bash 5.3 runs "${ cmd; }" and "${| cmd; }" as command substitution: a space, tab, newline or | right after the brace.
        if (end > _i + 2 && _s[_i + 2] is ' ' or '\t' or '\n' or '|')
        {
            return false;
        }

        for (var k = _i + 2; k < end; k++)
        {
            if (_s[k] is '\'' or '"' or '\\' or '`' or '$' or '{' or '\n' or '\0')
            {
                return false;
            }

            if (_s[k] is '<' or '>' && _s[k + 1] == '(')
            {
                return false;
            }
        }

        _inWord = true;
        _expands = true;
        _word.Append(_s, _i, end - _i + 1);
        _i = end + 1;
        return true;
    }

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
        _i = Ahead(op.Length);
        return true;
    }

    private bool Ampersand()
    {
        Flush();
        if (Peek(1) == '>')
        {
            var redirect = Peek(2) == '>' ? "&>>" : "&>";
            _tokens.Add(new ShellToken(ShellTokenKind.Redirect, redirect, true, false));
            _i = Ahead(redirect.Length);
            return true;
        }

        AddOperator(Peek(1) == '&' ? "&&" : "&");
        _i = Ahead(_tokens[^1].Text.Length);
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

            if (c == '`' || (c == '$' && Peek(1) is '(' or '['))
            {
                return false;
            }

            if (c == '$')
            {
                NoteDollar();
            }

            if (c == '$' && Peek(1) == '{')
            {
                if (!BracedExpansion())
                {
                    return false;
                }

                continue;
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
        if (_inWord && _plain && IsNamedDescriptor())
        {
            return false; // {name}>file opens a descriptor, which the parser does not model
        }

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
            _i = Ahead(2);
        }
        else
        {
            op = c.ToString();
            _i = Ahead(1);
        }

        _tokens.Add(new ShellToken(ShellTokenKind.Redirect, fd + op, true, false));
        return true;
    }

    private bool IsNamedDescriptor()
    {
        if (_word.Length < 3 || _word[0] != '{' || _word[^1] != '}' || char.IsAsciiDigit(_word[1]))
        {
            return false;
        }

        for (var k = 1; k < _word.Length - 1; k++)
        {
            if (!(char.IsAsciiLetterOrDigit(_word[k]) || _word[k] == '_'))
            {
                return false;
            }
        }

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
        _tokens.Add(new ShellToken(ShellTokenKind.Word, text, _plain, IsAssignment(text, _plainEnd), _expands));
        _word.Clear();
        _expands = false;
        _bracket = -1;
        _inWord = false;
        _plain = true;
        _plainEnd = -1;
    }

    // NAME=value or NAME+=value where NAME is a plain identifier typed without quotes or escapes.
    private static bool IsAssignment(string text, int plainEnd)
    {
        var eq = text.IndexOf('=', StringComparison.Ordinal);
        if (eq <= 0 || (plainEnd >= 0 && plainEnd <= eq) || char.IsAsciiDigit(text[0]))
        {
            return false;
        }

        var nameEnd = text[eq - 1] == '+' ? eq - 1 : eq;
        if (nameEnd == 0)
        {
            return false;
        }

        for (var k = 0; k < nameEnd; k++)
        {
            if (!(char.IsAsciiLetterOrDigit(text[k]) || text[k] == '_'))
            {
                return false;
            }
        }

        return true;
    }
}
