using System.Text.Json.Serialization;
using ZeroAlloc.Serialisation;

namespace AI.Sentinel.Tests.Detectors.Security;

[ZeroAllocSerializable(SerializationFormat.SystemTextJson)]
public sealed class WeatherResponse
{
    [JsonRequired]
    [JsonPropertyName("city")]
    public string City { get; set; } = "";

    [JsonRequired]
    [JsonPropertyName("temperatureC")]
    public double TemperatureC { get; set; }
}
