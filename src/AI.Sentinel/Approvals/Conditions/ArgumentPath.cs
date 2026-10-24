using System.Globalization;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace AI.Sentinel.Approvals.Conditions;

/// <summary>
/// A parsed JSON path into tool-call arguments. Supports <c>$</c> followed by <c>.name</c>,
/// <c>['name']</c> and <c>[n]</c> segments only. Quoted names may escape <c>'</c> and <c>\</c> with a backslash.
/// </summary>
internal sealed class ArgumentPath
{
    private static readonly JsonWriterOptions WriterOptions = new() { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };

    private readonly (string? Name, int Index)[] _segments;

    private ArgumentPath(string text, (string? Name, int Index)[] segments)
    {
        Text = text;
        _segments = segments;
    }

    /// <summary>The path as written.</summary>
    public string Text { get; }

    /// <summary>Parses <paramref name="path"/>; throws <see cref="ArgumentException"/> naming the path on bad syntax.</summary>
    public static ArgumentPath Parse(string path)
    {
        ArgumentNullException.ThrowIfNull(path);
        if (path.Length < 2 || path[0] != '$')
            throw Bad(path);

        var segments = new List<(string? Name, int Index)>();
        var i = 1;
        while (i < path.Length)
        {
            if (path[i] == '.')
            {
                var start = ++i;
                while (i < path.Length && IsNameChar(path[i])) i++;
                if (i == start) throw Bad(path);
                segments.Add((path.Substring(start, i - start), 0));
            }
            else if (path[i] == '[' && i + 1 < path.Length && path[i + 1] == '\'')
            {
                segments.Add((ReadQuotedName(path, ref i), 0));
            }
            else if (path[i] == '[')
            {
                var start = ++i;
                while (i < path.Length && path[i] is >= '0' and <= '9') i++;
                if (i == start || i >= path.Length || path[i] != ']'
                    || !int.TryParse(path.AsSpan(start, i - start), NumberStyles.None, CultureInfo.InvariantCulture, out var index))
                    throw Bad(path);
                segments.Add((null, index));
                i++;
            }
            else
            {
                throw Bad(path);
            }
        }

        return new ArgumentPath(path, segments.ToArray());
    }

    /// <summary>
    /// Resolves the path against <paramref name="args"/>. Returns false when the path does not resolve,
    /// the value is JSON null, or <paramref name="args"/> is not an object or array. Never throws.
    /// </summary>
    public bool TryGetMatchText(JsonElement args, out string text)
    {
        text = string.Empty;
        var current = args;
        foreach (var (name, index) in _segments)
        {
            if (name is not null)
            {
                if (current.ValueKind != JsonValueKind.Object || !current.TryGetProperty(name, out current))
                    return false;
            }
            else
            {
                if (current.ValueKind != JsonValueKind.Array || index >= current.GetArrayLength())
                    return false;
                current = current[index];
            }
        }

        switch (current.ValueKind)
        {
            case JsonValueKind.String:
                text = current.GetString() ?? string.Empty;
                return true;
            case JsonValueKind.Number:
            case JsonValueKind.True:
            case JsonValueKind.False:
                text = current.GetRawText();
                return true;
            case JsonValueKind.Object:
            case JsonValueKind.Array:
                using (var stream = new MemoryStream())
                {
                    using (var writer = new Utf8JsonWriter(stream, WriterOptions))
                        current.WriteTo(writer);
                    text = Encoding.UTF8.GetString(stream.GetBuffer(), 0, (int)stream.Length);
                }
                return true;
            default:
                return false;
        }
    }

    /// <summary>Reads <c>['name']</c> starting at the opening bracket; leaves <paramref name="i"/> after the closing bracket.</summary>
    private static string ReadQuotedName(string path, ref int i)
    {
        var name = new StringBuilder();
        var j = i + 2;
        var closed = false;
        while (j < path.Length)
        {
            var c = path[j];
            if (c == '\\')
            {
                if (j + 1 >= path.Length || path[j + 1] is not ('\'' or '\\')) throw Bad(path);
                name.Append(path[j + 1]);
                j += 2;
            }
            else if (c == '\'')
            {
                closed = true;
                break;
            }
            else
            {
                name.Append(c);
                j++;
            }
        }

        if (!closed || j + 1 >= path.Length || path[j + 1] != ']') throw Bad(path);
        i = j + 2;
        return name.ToString();
    }

    private static bool IsNameChar(char c) => char.IsLetterOrDigit(c) || c is '_' or '-';

    private static ArgumentException Bad(string path) =>
        new($"Invalid JSON path '{path}': expected '$' followed by .name, ['name'] or [n] segments.", nameof(path));
}
