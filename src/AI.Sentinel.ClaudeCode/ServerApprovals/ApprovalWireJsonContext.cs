using System.Text.Json.Serialization;

namespace AI.Sentinel.ClaudeCode.ServerApprovals;

/// <summary>Source generated serialization of the approval endpoints: no runtime reflection, safe under Native AOT.</summary>
[JsonSerializable(typeof(ApprovalRequestWire))]
[JsonSerializable(typeof(ApprovalStateWire))]
[JsonSerializable(typeof(ApprovalListWire))]
[JsonSerializable(typeof(ApprovalDecisionWire))]
[JsonSerializable(typeof(string))]
[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.SnakeCaseLower,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
internal sealed partial class ApprovalWireJsonContext : JsonSerializerContext;
