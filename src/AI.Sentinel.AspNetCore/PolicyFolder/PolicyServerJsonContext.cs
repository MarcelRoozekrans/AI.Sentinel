using System.Text.Json.Serialization;

namespace AI.Sentinel.AspNetCore.PolicyFolder;

[JsonSerializable(typeof(ProfileKeysResponse))]
internal sealed partial class PolicyServerJsonContext : JsonSerializerContext;
