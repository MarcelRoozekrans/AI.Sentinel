using System.Text;
using Microsoft.Extensions.AI;

namespace AI.Sentinel.Detection;

/// <summary>Recognises and decodes <see cref="DataContent"/> that a model reads as text, for redaction and detection alike.</summary>
internal static class TextData
{
    /// <summary>The text of <paramref name="data"/> when it is text-typed and its charset is supported; otherwise
    /// <see langword="null"/>, as for binary data such as an image.</summary>
    internal static string? Decode(DataContent data)
    {
        if (!IsText(data) || data.Data.IsEmpty) return null;
        return EncodingOf(data, failClosed: false) is { } encoding ? encoding.GetString(data.Data.Span) : null;
    }

    internal static Encoding? EncodingOf(DataContent data, bool failClosed)
    {
        var parameters = data.MediaType.Split(';');
        for (var i = 1; i < parameters.Length; i++)
        {
            var parameter = parameters[i].Trim();
            if (!parameter.StartsWith("charset=", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var name = parameter["charset=".Length..].Trim('"', ' ');
            Encoding? encoding = null;
            try
            {
                encoding = Encoding.GetEncoding(name);
            }
            catch (ArgumentException)
            {
                encoding = null;
            }

            if (encoding is null && !failClosed)
            {
                return null;
            }
            return encoding ?? throw new InvalidOperationException(
                "Text data content declares a charset that is not supported, so it cannot be scanned.");
        }
        return Encoding.UTF8;
    }

    // Text and the text-based application types a model reads as text: JSON, XML and their +json and +xml
    // variants, NDJSON, YAML, JavaScript and form data. Parameters such as charset are ignored here.
    internal static bool IsText(DataContent data)
    {
        var mediaType = data.MediaType.AsSpan();
        var semicolon = mediaType.IndexOf(';');
        if (semicolon >= 0)
        {
            mediaType = mediaType[..semicolon];
        }
        mediaType = mediaType.Trim();

        if (mediaType.StartsWith("text/", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }
        if (!mediaType.StartsWith("application/", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var subtype = mediaType["application/".Length..];
        foreach (var textual in TextApplicationSubtypes)
        {
            if (subtype.Equals(textual, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }
        return subtype.EndsWith("+json", StringComparison.OrdinalIgnoreCase)
            || subtype.EndsWith("+xml", StringComparison.OrdinalIgnoreCase);
    }

    private static readonly string[] TextApplicationSubtypes =
        ["json", "xml", "x-ndjson", "yaml", "x-yaml", "javascript", "x-www-form-urlencoded"];
}
