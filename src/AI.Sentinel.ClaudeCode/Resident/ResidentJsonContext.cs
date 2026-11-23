using System.Text.Json.Serialization;

namespace AI.Sentinel.ClaudeCode.Resident;

/// <summary>Source generated serialization of the local channel: no runtime reflection, safe under Native AOT.</summary>
[JsonSerializable(typeof(ResidentRequest))]
[JsonSerializable(typeof(ResidentResponse))]
[JsonSerializable(typeof(ResidentSeverity))]
[JsonSerializable(typeof(SignIn.TokenSet))]
[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.SnakeCaseLower,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
internal sealed partial class ResidentJsonContext : JsonSerializerContext;
