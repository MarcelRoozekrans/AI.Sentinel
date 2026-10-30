using System.Text;

namespace AI.Sentinel.Detection;

internal static class Utf8Text
{
    /// <summary>
    /// The longest prefix of <paramref name="text"/> whose UTF-8 encoding is at most <paramref name="maxBytes"/>
    /// bytes. A surrogate pair is kept whole or dropped whole, so the prefix never ends in a lone high surrogate.
    /// Returns <paramref name="text"/> itself when it fits.
    /// </summary>
    internal static string Truncate(string text, int maxBytes)
    {
        ArgumentNullException.ThrowIfNull(text);
        if (maxBytes <= 0) return string.Empty;
        if (Encoding.UTF8.GetByteCount(text) <= maxBytes) return text;

        var bytes = 0;
        var i = 0;
        while (i < text.Length)
        {
            var length = char.IsHighSurrogate(text[i]) && i + 1 < text.Length && char.IsLowSurrogate(text[i + 1]) ? 2 : 1;
            var size = Encoding.UTF8.GetByteCount(text.AsSpan(i, length));
            if (bytes + size > maxBytes) break;
            bytes += size;
            i += length;
        }

        return text[..i];
    }
}
