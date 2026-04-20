using System.Net.Http.Json;

namespace AI.Sentinel.Alerts;

public sealed class WebhookAlertSink(Uri endpoint) : IAlertSink
{
    private static readonly HttpClient _http = new();

    public async ValueTask SendAsync(SentinelError error, CancellationToken ct)
    {
        var payload = error switch
        {
            SentinelError.ThreatDetected t => new AlertPayload(
                "ThreatDetected",
                t.Result.Severity.ToString(),
                t.Result.DetectorId.ToString(),
                t.Result.Reason,
                t.Action.ToString()),
            SentinelError.PipelineFailure f => new AlertPayload(
                "PipelineFailure", "Unknown", "n/a", f.Message, "n/a"),
            _ => new AlertPayload("Unknown", "Unknown", "n/a", string.Empty, "n/a")
        };

#pragma warning disable ERP022 // fire-and-forget: webhook failure must never surface to the caller
        try
        {
            await _http.PostAsJsonAsync(endpoint, payload, ct).ConfigureAwait(false);
        }
        catch
        {
            // intentionally swallowed — webhook is best-effort only
        }
#pragma warning restore ERP022
    }

    private sealed record AlertPayload(
        string Type,
        string Severity,
        string Detector,
        string Reason,
        string Action);
}
