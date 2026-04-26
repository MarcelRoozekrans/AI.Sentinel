using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace AI.Sentinel.Mcp;

[JsonSerializable(typeof(IDictionary<string, JsonElement>))]
[JsonSerializable(typeof(IReadOnlyDictionary<string, JsonElement>))]
[JsonSerializable(typeof(IReadOnlyDictionary<string, string>))]
[JsonSourceGenerationOptions(WriteIndented = false)]
internal sealed partial class McpJsonContext : JsonSerializerContext;
