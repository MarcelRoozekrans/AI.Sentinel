using System.Text.Json;
using Microsoft.Extensions.AI;

namespace AI.Sentinel.Cli;

public static class ConversationLoader
{
    private static readonly JsonSerializerOptions _jsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
    };

    public static async Task<LoadedConversation> LoadAsync(
        string path,
        ConversationFormat format = ConversationFormat.Auto,
        CancellationToken cancellationToken = default)
    {
        if (!File.Exists(path))
            throw new FileNotFoundException($"Conversation file not found: {path}", path);

        var content = await File.ReadAllTextAsync(path, cancellationToken).ConfigureAwait(false);
        var resolvedFormat = format == ConversationFormat.Auto
            ? DetectFormat(path, content)
            : format;

        var turns = resolvedFormat switch
        {
            ConversationFormat.OpenAIChatCompletion => ParseOpenAI(content),
            ConversationFormat.AuditNdjson => ParseNdjson(content),
            _ => throw new InvalidDataException(
                $"Cannot load: format {resolvedFormat} is not supported."),
        };

        return new LoadedConversation(resolvedFormat, turns);
    }

    private static ConversationFormat DetectFormat(string path, string content)
    {
        var ext = Path.GetExtension(path).ToLowerInvariant();
        if (ext is ".ndjson" or ".jsonl") return ConversationFormat.AuditNdjson;

        var trimmed = content.TrimStart();
        if (trimmed.StartsWith('{') && trimmed.Contains("\"messages\"", StringComparison.Ordinal))
        {
            try
            {
                using var doc = JsonDocument.Parse(trimmed);
                if (doc.RootElement.ValueKind == JsonValueKind.Object
                    && doc.RootElement.TryGetProperty("messages", out var messages)
                    && messages.ValueKind == JsonValueKind.Array)
                    return ConversationFormat.OpenAIChatCompletion;
            }
            catch (JsonException) { }
        }

        var firstLine = content.Split('\n', 2)[0].Trim();
        if (firstLine.StartsWith('{'))
        {
            try
            {
                using var _ = JsonDocument.Parse(firstLine);
                return ConversationFormat.AuditNdjson;
            }
            catch (JsonException) { }
        }

        throw new InvalidDataException(
            "Could not auto-detect conversation format. Pass --format openai or --format audit explicitly.");
    }

    private static IReadOnlyList<ConversationTurn> ParseOpenAI(string content)
    {
        var root = JsonSerializer.Deserialize<OpenAiEnvelope>(content, _jsonOptions)
            ?? throw new InvalidDataException("OpenAI conversation root was null.");
        return BuildTurnsFromMessages(root.Messages ?? []);
    }

    private static IReadOnlyList<ConversationTurn> ParseNdjson(string content)
    {
        var turns = new List<ConversationTurn>();
        foreach (var rawLine in content.Split('\n'))
        {
            var line = rawLine.Trim();
            if (line.Length == 0) continue;
            var envelope = JsonSerializer.Deserialize<OpenAiEnvelope>(line, _jsonOptions)
                ?? throw new InvalidDataException($"NDJSON line was null: {line}");
            turns.AddRange(BuildTurnsFromMessages(envelope.Messages ?? []));
        }
        return turns;
    }

    private static IReadOnlyList<ConversationTurn> BuildTurnsFromMessages(IReadOnlyList<MessageDto> messages)
    {
        var turns = new List<ConversationTurn>();
        var priorMessages = new List<ChatMessage>();
        foreach (var m in messages)
        {
            var chatMessage = new ChatMessage(ParseRole(m.Role), m.Content ?? "");
            if (chatMessage.Role == ChatRole.Assistant)
            {
                turns.Add(new ConversationTurn(priorMessages.ToArray(), chatMessage));
            }
            priorMessages.Add(chatMessage);
        }
        return turns;
    }

    private static ChatRole ParseRole(string? role) => role?.ToLowerInvariant() switch
    {
        "system" => ChatRole.System,
        "user" => ChatRole.User,
        "assistant" => ChatRole.Assistant,
        "tool" => ChatRole.Tool,
        _ => ChatRole.User,
    };

    private sealed class OpenAiEnvelope
    {
        public List<MessageDto>? Messages { get; set; }
    }

    private sealed class MessageDto
    {
        public string? Role { get; set; }
        public string? Content { get; set; }
    }
}
