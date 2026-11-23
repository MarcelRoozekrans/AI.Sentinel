using System.Text.RegularExpressions;

namespace AI.Sentinel.ClaudeCode.Events;

/// <summary>
/// Makes a reason fit to leave the machine (ADR-247). It is only used with detailed logging. A reason that looks like it holds a
/// secret is dropped whole. Any other has its URLs, email addresses, quoted values and paths replaced, so what is left names the rule
/// and not what the developer was working on.
/// </summary>
internal static partial class ReasonRedactor
{
    /// <summary>The longest reason sent; the server refuses more.</summary>
    public const int MaxLength = 1800;

    /// <summary>The redacted <paramref name="reason"/>, or <see langword="null"/> when nothing of it is left to send or it looks like it
    /// holds a secret.</summary>
    public static string? Redact(string? reason)
    {
        if (string.IsNullOrWhiteSpace(reason) || LooksSecret(reason))
        {
            return null;
        }

        var text = Url().Replace(reason, "<url>");
        text = Email().Replace(text, "<email>");
        text = Quoted().Replace(text, "<value>");
        text = WindowsPath().Replace(text, "<path>");
        text = UnixPath().Replace(text, "<path>");
        text = text.Trim();
        if (text.Length > MaxLength)
        {
            text = text[..MaxLength];
        }

        return text.Length == 0 ? null : text;
    }

    /// <summary>True for text that holds a key, a token, a private key or a credential assignment, or a long run of random-looking
    /// characters. Checked on the text as it is, before a quoted value is hidden, because a secret is often quoted.</summary>
    internal static bool LooksSecret(string text) =>
        SecretShape().IsMatch(text) || Assignment().IsMatch(text) || RandomRun().Matches(text).Any(m => IsMixed(m.Value));

    private static bool IsMixed(string run)
    {
        var upper = false;
        var lower = false;
        var digit = false;
        foreach (var c in run)
        {
            upper |= char.IsAsciiLetterUpper(c);
            lower |= char.IsAsciiLetterLower(c);
            digit |= char.IsAsciiDigit(c);
        }

        return digit && ((upper && lower) || (run.Length >= 32 && (upper || lower)));
    }

    [GeneratedRegex(@"-----BEGIN [A-Z ]*PRIVATE KEY|\bAKIA[0-9A-Z]{16}\b|\bgh[pousr]_[A-Za-z0-9]{20,}|\bgithub_pat_[A-Za-z0-9_]{20,}|\bsk-[A-Za-z0-9_\-]{16,}|\bxox[abprs]-[A-Za-z0-9\-]{10,}|\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]*|\bBearer\s+[A-Za-z0-9._~+/\-]{12,}", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 200)]
    private static partial Regex SecretShape();

    [GeneratedRegex(@"\b(?:pass(?:word|wd)?|secret|token|api[_\-]?key|access[_\-]?key|private[_\-]?key|credential)s?\b\s*[=:]\s*\S", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase, matchTimeoutMilliseconds: 200)]
    private static partial Regex Assignment();

    [GeneratedRegex(@"[A-Za-z0-9+/=_\-]{24,}", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 200)]
    private static partial Regex RandomRun();

    [GeneratedRegex(@"\b[A-Za-z][A-Za-z0-9+.\-]*://[^\s'""<>)\]]+", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 200)]
    private static partial Regex Url();

    [GeneratedRegex(@"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 200)]
    private static partial Regex Email();

    // A quoted value: single, double or backtick quotes. An apostrophe inside a word (don't) opens no quote, because the character
    // before it is a letter and the one after it is a letter.
    [GeneratedRegex(@"(?<![A-Za-z])'[^'\r\n]*'|""[^""\r\n]*""|`[^`\r\n]*`", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 200)]
    private static partial Regex Quoted();

    [GeneratedRegex(@"\b[A-Za-z]:\\[^\s'""<>|]*|\\\\[^\s'""<>|]+", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 200)]
    private static partial Regex WindowsPath();

    [GeneratedRegex(@"(?<![\w<>.:/])(?:~|\.{1,2})?/[^\s'"",;:)\]]+", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 200)]
    private static partial Regex UnixPath();
}
