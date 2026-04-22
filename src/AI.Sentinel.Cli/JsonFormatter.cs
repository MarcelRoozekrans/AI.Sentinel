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
        => JsonSerializer.Deserialize<ReplayResult>(json, _options)
           ?? throw new InvalidDataException("Failed to deserialize ReplayResult.");
}
