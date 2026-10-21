using System.Text;
using System.Text.Json;

namespace AI.Sentinel.Redaction;

/// <summary>
/// One piece of content a host, such as the MCP proxy or a hook CLI, hands Sentinel on its way to the model: text,
/// or JSON whose string values are redacted while its shape is kept. Exactly one of <see cref="Text"/> and
/// <see cref="Json"/> is set. <see cref="ToString"/> never prints the content.
/// </summary>
internal readonly record struct HostContent
{
    private HostContent(string? text, JsonElement? json)
    {
        Text = text;
        Json = json;
    }

    /// <summary>The text, when this is text content.</summary>
    public string? Text { get; }

    /// <summary>The JSON, when this is JSON content.</summary>
    public JsonElement? Json { get; }

    /// <summary>Text content.</summary>
    public static HostContent FromText(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        return new HostContent(text, null);
    }

    /// <summary>JSON content; <paramref name="json"/> must hold a value.</summary>
    public static HostContent FromJson(JsonElement json)
    {
        if (json.ValueKind == JsonValueKind.Undefined)
        {
            throw new ArgumentException("JSON content must hold a value.", nameof(json));
        }
        return new HostContent(null, json);
    }

    /// <summary>The kind of content only, never the content.</summary>
    public override string ToString() => Json is null ? "HostContent { Text }" : "HostContent { Json }";

    /// <summary>
    /// The text the detectors judge: the text, or the JSON with every name and string written as the characters it
    /// holds. Only <c>"</c> and <c>\</c> are escaped, so non-ASCII text, zero-width characters and
    /// <c>&lt; &gt; &amp; ' +</c> reach the detectors as they are and never as <c>\uXXXX</c>, whichever escaping
    /// the input or a JSON writer used. A space follows every <c>,</c> and <c>:</c>, so a value at the end of a string
    /// ends at whitespace, as it does when the string is redacted on its own: a placeholder that ends a string is then
    /// judged as the placeholder, not run on into the next member. It is for scanning only and is not sent anywhere.
    /// </summary>
    internal string ScanText()
    {
        if (Text is not null)
        {
            return Text;
        }

        var sb = new StringBuilder();
        Render(Json!.Value, sb);
        return sb.ToString();
    }

    private static void Render(JsonElement element, StringBuilder sb)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.String:
                AppendString(element.GetString()!, sb);
                break;
            case JsonValueKind.Object:
                sb.Append('{');
                var firstProperty = true;
                foreach (var property in element.EnumerateObject())
                {
                    if (!firstProperty)
                    {
                        sb.Append(", ");
                    }
                    firstProperty = false;
                    AppendString(property.Name, sb);
                    sb.Append(": ");
                    Render(property.Value, sb);
                }
                sb.Append('}');
                break;
            case JsonValueKind.Array:
                sb.Append('[');
                var firstItem = true;
                foreach (var item in element.EnumerateArray())
                {
                    if (!firstItem)
                    {
                        sb.Append(", ");
                    }
                    firstItem = false;
                    Render(item, sb);
                }
                sb.Append(']');
                break;
            default:
                // Numbers, booleans and null: their raw text holds no escapes.
                sb.Append(element.GetRawText());
                break;
        }
    }

    private static void AppendString(string value, StringBuilder sb)
    {
        sb.Append('"');
        foreach (var c in value)
        {
            if (c is '"' or '\\')
            {
                sb.Append('\\');
            }
            sb.Append(c);
        }
        sb.Append('"');
    }
}
