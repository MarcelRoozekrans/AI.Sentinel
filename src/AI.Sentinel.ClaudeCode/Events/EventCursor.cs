using System.Text.Json;
using AI.Sentinel.ClaudeCode.Policy.Rego;

namespace AI.Sentinel.ClaudeCode.Events;

/// <summary>The sequence of the last audit entry the server has taken, kept in the state folder with the audit file and the server it
/// belongs to. It moves only after the server accepted a batch, so an entry is never skipped, and one that is sent again keeps its event
/// id.</summary>
internal sealed class EventCursor(string directory)
{
    /// <summary>The file name.</summary>
    public const string FileName = "events-cursor.json";

    private string Path => System.IO.Path.Combine(directory, FileName);

    /// <summary>The stored sequence, or <see langword="null"/> when there is none yet or the file cannot be used.</summary>
    public long? Read() => ReadContent()?.Sequence;

    /// <summary>The stored cursor, or <see langword="null"/> when there is none yet or the file cannot be used.</summary>
    public EventCursorContent? ReadContent()
    {
        try
        {
            return PolicyCache.TryRead(Path) is { } bytes
                ? JsonSerializer.Deserialize(bytes, EventsJsonContext.Default.EventCursorContent)
                : null;
        }
        catch (Exception e) when (e is JsonException or IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    /// <summary>Replaces the stored cursor with <paramref name="content"/>, whole.</summary>
    public void Write(EventCursorContent content) =>
        PolicyCache.Write(Path, JsonSerializer.SerializeToUtf8Bytes(content, EventsJsonContext.Default.EventCursorContent));
}
