using System.Text.Json.Serialization;

namespace AI.Sentinel.ClaudeCode.SignIn;

[JsonSerializable(typeof(OidcDiscovery))]
[JsonSerializable(typeof(DeviceAuthorizationWire))]
[JsonSerializable(typeof(TokenResponseWire))]
[JsonSerializable(typeof(ProfileKeysWire))]
[JsonSourceGenerationOptions(DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
internal sealed partial class SignInJsonContext : JsonSerializerContext;
