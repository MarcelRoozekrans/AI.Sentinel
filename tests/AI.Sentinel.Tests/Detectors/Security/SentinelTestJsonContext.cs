using System.Text.Json.Serialization;

namespace AI.Sentinel.Tests.Detectors.Security;

/// <summary>
/// AOT registration for the serializable test types.
/// <para>
/// ZeroAlloc.Serialisation 2.x (analyzer <c>ZASZ004</c>) requires every type marked
/// <c>[ZeroAllocSerializable(SerializationFormat.SystemTextJson)]</c> to appear on a
/// <see cref="JsonSerializerContext"/>-derived class in the same compilation, so the
/// generated serializer has a trim-safe <c>JsonTypeInfo</c> to bind to instead of
/// falling back to reflection.
/// </para>
/// </summary>
[JsonSerializable(typeof(WeatherResponse))]
internal sealed partial class SentinelTestJsonContext : JsonSerializerContext;
