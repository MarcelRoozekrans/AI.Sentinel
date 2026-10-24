using System.Buffers;
using System.Text;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using ZeroAlloc.Inject;
namespace AI.Sentinel.Detectors.Security;

[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed class AdversarialUnicodeDetector : IDetector
{
    private static readonly DetectorId _id = new("SEC-24");
    private static readonly DetectionResult _clean = DetectionResult.Clean(_id);

    public DetectorId Id => _id;
    public DetectorCategory Category => DetectorCategory.Security;

    private static bool IsSuspicious(char c) =>
        c is '\u200b' or '\u200c' or '\u200d' or '\ufeff' or '\u2060'
        || (c >= '\u202a' && c <= '\u202e')
        || (c >= '\u2066' && c <= '\u2069');

    /// <summary>
    /// A joiner that writing systems need: U+200D, zero width joiner, between two emoji, as in a family or
    /// heart-on-fire sequence, and U+200C, zero width non-joiner, between two Arabic-script or Indic letters, as in
    /// Persian or Hindi. Elsewhere, between Latin letters for example, they only hide or split words.
    /// </summary>
    private static bool IsLegitimateJoiner(string text, int index)
    {
        var c = text[index];
        if (c is not ('\u200d' or '\u200c')) return false;

        if (!TryPrevious(text, index, out var previous) || !TryNext(text, index, out var next)) return false;

        return c == '\u200d'
            ? IsEmoji(previous) && IsEmoji(next)
            : IsJoiningScript(previous) && IsJoiningScript(next);
    }

    /// <summary>
    /// U+FEFF where a byte order mark sits: at the start of the text, of a JSON string value or of a line, the last one
    /// raw or JSON-escaped. A file saved with a UTF-8 BOM keeps it when a tool reads it with fs.readFile or cat, so it
    /// opens a tool result, or a file's lines in one. There it hides nothing: it splits no word, and a second U+FEFF
    /// after it still counts.
    /// </summary>
    private static bool IsByteOrderMark(string text, int index)
    {
        if (text[index] != '\ufeff') return false;
        if (index == 0) return true;

        var previous = text[index - 1];
        if (previous is '\n' or '\r') return true;
        if (previous == '"') return OpensJsonValue(text, index - 1);
        return previous is ('n' or 'r') && IsEscaped(text, index - 1);
    }

    /// <summary>Whether the quote at <paramref name="quote"/> follows a colon, compact or with spaces between.</summary>
    private static bool OpensJsonValue(string text, int quote)
    {
        var i = quote - 1;
        while (i >= 0 && text[i] == ' ') i--;
        return i >= 0 && text[i] == ':';
    }

    /// <summary>Whether an odd run of backslashes precedes <paramref name="index"/>, so the character there is escaped.</summary>
    private static bool IsEscaped(string text, int index)
    {
        var backslashes = 0;
        for (var i = index - 1; i >= 0 && text[i] == '\\'; i--) backslashes++;
        return backslashes % 2 == 1;
    }

    /// <summary>The code point before <paramref name="index"/>, skipping an emoji presentation selector.</summary>
    private static bool TryPrevious(string text, int index, out Rune rune)
    {
        var before = text.AsSpan(0, index);
        while (Rune.DecodeLastFromUtf16(before, out rune, out var length) == OperationStatus.Done)
        {
            if (rune.Value is not (0xFE0F or 0xFE0E)) return true;
            before = before[..^length];
        }
        return false;
    }

    private static bool TryNext(string text, int index, out Rune rune) =>
        Rune.DecodeFromUtf16(text.AsSpan(index + 1), out rune, out _) == OperationStatus.Done;

    /// <summary>Pictographic and symbol blocks emoji are drawn from, skin-tone modifiers included. Tag characters, which
    /// close a flag sequence, are not: they never sit on either side of a joiner.</summary>
    private static bool IsEmoji(Rune rune) => rune.Value is
        (>= 0x1F000 and <= 0x1FAFF)
        or (>= 0x2600 and <= 0x27BF)
        or (>= 0x2B00 and <= 0x2BFF)
        or (>= 0x2190 and <= 0x21FF)
        or (>= 0x2300 and <= 0x23FF);

    /// <summary>Arabic-script and Indic blocks, combining marks such as a virama included.</summary>
    private static bool IsJoiningScript(Rune rune) => rune.Value is
        (>= 0x0600 and <= 0x06FF)
        or (>= 0x0750 and <= 0x077F)
        or (>= 0x08A0 and <= 0x08FF)
        or (>= 0xFB50 and <= 0xFDFF)
        or (>= 0xFE70 and <= 0xFEFC)
        or (>= 0x0900 and <= 0x0DFF);

    public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
    {
        var count = 0;
        // Tool calls and results count: hidden characters in retrieved content are a classic smuggling route.
        foreach (var message in ctx.Messages)
        {
            var text = SentinelContext.MessageText(message);
            for (var i = 0; i < text.Length; i++)
            {
                if (IsSuspicious(text[i]) && !IsLegitimateJoiner(text, i) && !IsByteOrderMark(text, i))
                    count++;
            }
        }

        if (count == 0) return ValueTask.FromResult(_clean);

        var severity = count > 2 ? Severity.High : Severity.Medium;
        return ValueTask.FromResult(DetectionResult.WithSeverity(_id, severity,
            $"Adversarial Unicode: {count} suspicious character(s) detected"));
    }
}
