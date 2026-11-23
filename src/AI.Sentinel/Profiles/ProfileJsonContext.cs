using System.Text.Json.Serialization;

namespace AI.Sentinel.Profiles;

/// <summary>Source-generated JSON metadata for reading profiles and the signed envelope. No reflection, Native AOT safe.</summary>
[JsonSerializable(typeof(PolicyProfile))]
[JsonSerializable(typeof(SignedProfile))]
[JsonSourceGenerationOptions(UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow)]
internal sealed partial class ProfileJsonContext : JsonSerializerContext;
