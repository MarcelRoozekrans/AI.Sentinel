using System.Globalization;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace AI.Sentinel.Detection;

/// <summary>
/// The shape of a redaction placeholder: <c>[TYPE_n_tag]</c>, such as <c>[EMAIL_1_k3f9x2]</c>. TYPE is upper-case
/// letters, digits and underscores, n counts per type within one call from 1, and tag is drawn at random for every
/// call: a lower-case letter and five lower-case letters or digits. A token from another call, or from another
/// model round trip, carries another tag, so it never resolves to a value of this call and stays literal text.
/// </summary>
internal static partial class PlaceholderFormat
{
    /// <summary>Characters in a tag after its first one.</summary>
    private const string TagChars = "abcdefghijklmnopqrstuvwxyz0123456789";

    private const string TagLetters = "abcdefghijklmnopqrstuvwxyz";

    /// <summary>The length of a tag.</summary>
    public const int TagLength = 6;

    /// <summary>Any placeholder-shaped token, whatever its tag.</summary>
    [GeneratedRegex(@"\[[A-Z0-9_]+_\d+_[a-z][a-z0-9]{5}\]", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 1000)]
    public static partial Regex Pattern();

    /// <summary>
    /// A new random tag. 26 times 36 to the fifth, about 1.6 billion, values: two calls of one conversation share a
    /// tag by chance only negligibly often, and text written before a call cannot name its tokens.
    /// </summary>
    public static string NewTag() =>
        RandomNumberGenerator.GetString(TagLetters, 1) + RandomNumberGenerator.GetString(TagChars, TagLength - 1);

    /// <summary>The token for the <paramref name="n"/>-th value of <paramref name="type"/> in the call tagged <paramref name="tag"/>.</summary>
    public static string Format(string type, int n, string tag) =>
        string.Create(CultureInfo.InvariantCulture, $"[{type}_{n}_{tag}]");

    /// <summary>True when <paramref name="tag"/> has the shape of a tag.</summary>
    public static bool IsTag(ReadOnlySpan<char> tag)
    {
        if (tag.Length != TagLength || tag[0] is < 'a' or > 'z')
        {
            return false;
        }

        foreach (var c in tag[1..])
        {
            if (c is not ((>= 'a' and <= 'z') or (>= '0' and <= '9')))
            {
                return false;
            }
        }
        return true;
    }

    /// <summary>True when <paramref name="inner"/>, the text between the brackets, is <c>TYPE_n_tag</c>.</summary>
    public static bool IsInner(ReadOnlySpan<char> inner)
    {
        if (inner.Length < TagLength + 4 || inner[^(TagLength + 1)] != '_' || !IsTag(inner[^TagLength..]))
        {
            return false;
        }

        var rest = inner[..^(TagLength + 1)];
        var underscore = rest.LastIndexOf('_');
        if (underscore <= 0 || underscore == rest.Length - 1)
        {
            return false;
        }

        foreach (var c in rest[..underscore])
        {
            if (c is not ((>= 'A' and <= 'Z') or (>= '0' and <= '9') or '_'))
            {
                return false;
            }
        }
        foreach (var c in rest[(underscore + 1)..])
        {
            if (c is < '0' or > '9')
            {
                return false;
            }
        }
        return true;
    }
}
