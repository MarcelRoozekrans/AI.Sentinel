using System.Text.Json;
using System.Text.Json.Serialization;

namespace AI.Sentinel.Cli;

public static class JsonFormatter
{
    private static readonly JsonSerializerOptions _options = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
    };

    public static string Format(ReplayResult result)
    {
        ArgumentNullException.ThrowIfNull(result);
        return JsonSerializer.Serialize(result, _options);
    }

    public static ReplayResult Deserialize(string json)
    {
        var result = JsonSerializer.Deserialize<ReplayResult>(json, _options)
           ?? throw new InvalidDataException("Failed to deserialize ReplayResult.");
        if (!string.Equals(result.SchemaVersion, ReplayRunner.CurrentSchemaVersion, StringComparison.Ordinal))
            throw new InvalidDataException(
                $"Unsupported schema version '{result.SchemaVersion}'; this tool emits and reads '{ReplayRunner.CurrentSchemaVersion}'.");
        return result;
    }
}
