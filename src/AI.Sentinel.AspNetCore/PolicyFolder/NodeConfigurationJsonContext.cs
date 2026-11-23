using System.Text.Json.Serialization;

namespace AI.Sentinel.AspNetCore.PolicyFolder;

[JsonSerializable(typeof(NodeConfigurationWire))]
[JsonSerializable(typeof(Dictionary<string, string>))]
[JsonSourceGenerationOptions(PropertyNameCaseInsensitive = false, UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow)]
internal sealed partial class NodeConfigurationJsonContext : JsonSerializerContext;
