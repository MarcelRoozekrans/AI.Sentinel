using System.Text.Json.Serialization;

namespace AI.Sentinel.Alerts;

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(WebhookAlertSink.AlertPayload))]
internal sealed partial class AlertJsonContext : JsonSerializerContext;
