using System.Text;

namespace AI.Sentinel.Redaction;

/// <summary>
/// How JSON reads to the detectors: every name and string written as the characters it holds, quoted, with only
/// <c>"</c> and <c>\</c> escaped, and a member written as <c>"name": "value"</c>. <see cref="HostContent.ScanText"/>
/// renders whole documents this way, and <see cref="RedactionSession"/> renders one member this way to redact a
/// value in the context of its key, so the scan and the redaction judge the same text.
/// </summary>
internal static class JsonScanText
{
    /// <summary>Appends <paramref name="value"/> quoted, escaping only <c>"</c> and <c>\</c>.</summary>
    public static void AppendString(string value, StringBuilder sb) => AppendQuoted(value, sb, escapes: null);

    /// <summary>Appends <c>"name": </c>, which precedes the value of a member.</summary>
    public static void AppendPropertyName(string name, StringBuilder sb)
    {
        AppendString(name, sb);
        sb.Append(": ");
    }

    /// <summary>The member <paramref name="name"/> with the string <paramref name="value"/>, rendered as the scan
    /// renders it.</summary>
    public static RenderedMember RenderMember(string name, string value)
    {
        var sb = new StringBuilder(name.Length + value.Length + 6);
        AppendPropertyName(name, sb);
        var valueStart = sb.Length + 1;
        var escapes = new List<int>();
        AppendQuoted(value, sb, escapes);
        return new RenderedMember(sb.ToString(), valueStart, sb.Length - 1, escapes.Count == 0 ? null : escapes);
    }

    // The one escaping routine. escapes, when given, receives the offset in sb of every backslash added.
    private static void AppendQuoted(string value, StringBuilder sb, List<int>? escapes)
    {
        sb.Append('"');
        foreach (var c in value)
        {
            if (c is '"' or '\\')
            {
                escapes?.Add(sb.Length);
                sb.Append('\\');
            }
            sb.Append(c);
        }
        sb.Append('"');
    }
}
