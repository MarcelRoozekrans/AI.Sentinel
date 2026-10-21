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

    /// <summary>The text the detectors judge: the text, or the JSON as written.</summary>
    internal string ScanText() => Text ?? Json!.Value.GetRawText();
}
