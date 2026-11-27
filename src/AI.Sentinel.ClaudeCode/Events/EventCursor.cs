using System.Text.Json;
using AI.Sentinel.ClaudeCode.Policy.Rego;

namespace AI.Sentinel.ClaudeCode.Events;

/// <summary>The sequence of the last audit entry the server has taken, kept in the state folder. It moves only after the server
/// accepted a batch, so an entry is never skipped, and one that is sent again keeps its event id.</summary>
internal sealed class EventCursor(string directory)
{
    /// <summary>The file name.</summary>
    public const string FileName = "events-cursor.json";

    private string Path => System.IO.Path.Combine(directory, FileName);

    /// <summary>The stored sequence, or <see langword="null"/> when there is none yet or the file cannot be used.</summary>
    public long? Read()
    {
        try
        {
            return PolicyCache.TryRead(Path) is { } bytes
                ? JsonSerializer.Deserialize(bytes, EventsJsonContext.Default.EventCursorContent)?.Sequence
                : null;
        }
        catch (Exception e) when (e is JsonException or IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    /// <summary>Stores <paramref name="sequence"/>.</summary>
    public void Write(long sequence) =>
        PolicyCache.Write(Path, JsonSerializer.SerializeToUtf8Bytes(new EventCursorContent { Sequence = sequence }, EventsJsonContext.Default.EventCursorContent));
}
