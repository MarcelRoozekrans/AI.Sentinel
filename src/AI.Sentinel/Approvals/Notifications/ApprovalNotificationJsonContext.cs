using System.Text.Json.Serialization;

namespace AI.Sentinel.Approvals.Notifications;

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(ApprovalNotification))]
internal sealed partial class ApprovalNotificationJsonContext : JsonSerializerContext;
