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
        return Truncate(text, Encoding.UTF8.GetByteCount(text), maxBytes, out _);
    }

    /// <summary>
    /// As <see cref="Truncate(string, int)"/>, for a caller that has already counted the
    /// <paramref name="textBytes"/> UTF-8 bytes of <paramref name="text"/>. <paramref name="keptBytes"/> is the UTF-8
    /// byte count of the prefix returned, so the caller need not count it again.
    /// </summary>
    internal static string Truncate(string text, int textBytes, int maxBytes, out int keptBytes)
    {
        ArgumentNullException.ThrowIfNull(text);
        if (maxBytes <= 0)
        {
            keptBytes = 0;
            return string.Empty;
        }

        if (textBytes <= maxBytes)
        {
            keptBytes = textBytes;
            return text;
        }

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

        keptBytes = bytes;
        return text[..i];
    }
}
