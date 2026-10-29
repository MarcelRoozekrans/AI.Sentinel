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

    /// <summary>Tag characters, U+E0000–E007F. They mirror ASCII and render invisibly, so a run of them can carry a
    /// whole hidden instruction that a model still reads.</summary>
    private static bool IsTag(Rune rune) => rune.Value is >= 0xE0000 and <= 0xE007F;

    /// <summary>Variation selectors, U+FE00–FE0F and U+E0100–E01EF. A run of them after a visible character can encode
    /// arbitrary bytes, one selector per byte.</summary>
    private static bool IsVariationSelector(Rune rune) => rune.Value is (>= 0xFE00 and <= 0xFE0F) or (>= 0xE0100 and <= 0xE01EF);

    /// <summary>The index just past the run of tag characters that starts at <paramref name="start"/>.</summary>
    private static int TagRunEnd(string text, int start)
    {
        var i = start;
        while (Rune.DecodeFromUtf16(text.AsSpan(i), out var rune, out var length) == OperationStatus.Done && IsTag(rune))
            i += length;
        return i;
    }

    private static int CountRunes(string text, int start, int end)
    {
        var count = 0;
        for (var i = start; i < end; i += char.IsHighSurrogate(text[i]) ? 2 : 1) count++;
        return count;
    }

    /// <summary>
    /// A subdivision flag such as England's: the black flag U+1F3F4, then a subdivision code of 3 to 6 tag digits or
    /// lowercase tag letters, closed by the cancel tag U+E007F. Any other tag run, uppercase or spaces included, is text.
    /// </summary>
    private static bool IsSubdivisionFlag(string text, int start, int end)
    {
        if (Rune.DecodeLastFromUtf16(text.AsSpan(0, start), out var before, out _) != OperationStatus.Done
            || before.Value != 0x1F3F4)
        {
            return false;
        }

        var code = 0;
        for (var i = start; i < end; i += 2)
        {
            var value = char.ConvertToUtf32(text[i], text[i + 1]);
            if (i + 2 == end) return value == 0xE007F && code is >= 3 and <= 6;
            if (value is not ((>= 0xE0030 and <= 0xE0039) or (>= 0xE0061 and <= 0xE007A))) return false;
            code++;
        }
        return false;
    }

    /// <summary>
    /// One selector right after a visible character, as in text-style or emoji-style presentation, a keycap or a
    /// standardized variant. A selector from U+E0100 upward only follows a CJK ideograph, as in an ideographic variation
    /// sequence for a name. Two selectors in a row, or one after a space or at the start, only hide data.
    /// </summary>
    private static bool IsSingleSelectorOnABase(string text, int index, Rune selector, int length)
    {
        if (Rune.DecodeLastFromUtf16(text.AsSpan(0, index), out var previous, out _) != OperationStatus.Done
            || IsVariationSelector(previous) || IsTag(previous) || Rune.IsWhiteSpace(previous) || Rune.IsControl(previous))
        {
            return false;
        }

        if (Rune.DecodeFromUtf16(text.AsSpan(index + length), out var next, out _) == OperationStatus.Done
            && IsVariationSelector(next))
        {
            return false;
        }

        return selector.Value <= 0xFE0F || IsCjkIdeograph(previous);
    }

    /// <summary>CJK unified and compatibility ideographs, the bases of ideographic variation sequences.</summary>
    private static bool IsCjkIdeograph(Rune rune) => rune.Value is
        (>= 0x3400 and <= 0x4DBF)
        or (>= 0x4E00 and <= 0x9FFF)
        or (>= 0xF900 and <= 0xFAFF)
        or (>= 0x20000 and <= 0x323AF);

    public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
    {
        var count = 0;
        // Tool calls and results count: hidden characters in retrieved content are a classic smuggling route.
        foreach (var message in ctx.Messages)
        {
            var text = SentinelContext.MessageText(message);
            for (var i = 0; i < text.Length; i++)
            {
                if (Rune.DecodeFromUtf16(text.AsSpan(i), out var rune, out var length) != OperationStatus.Done)
                    continue;

                if (IsTag(rune))
                {
                    var end = TagRunEnd(text, i);
                    if (!IsSubdivisionFlag(text, i, end)) count += CountRunes(text, i, end);
                    i = end - 1;
                }
                else if (IsVariationSelector(rune))
                {
                    if (!IsSingleSelectorOnABase(text, i, rune, length)) count++;
                }
                else if (IsSuspicious(text[i]) && !IsLegitimateJoiner(text, i) && !IsByteOrderMark(text, i))
                {
                    count++;
                }

                i += length - 1;
            }
        }

        if (count == 0) return ValueTask.FromResult(_clean);

        var severity = count > 2 ? Severity.High : Severity.Medium;
        return ValueTask.FromResult(DetectionResult.WithSeverity(_id, severity,
            $"Adversarial Unicode: {count} suspicious character(s) detected"));
    }
}
