using System.Net.Http.Json;

namespace AI.Sentinel.Alerts;

/// <summary>Delivers alert notifications to an HTTP webhook endpoint as JSON payloads.</summary>
/// <remarks>Failures are silently swallowed so a webhook outage never propagates back to the pipeline.</remarks>
/// <param name="endpoint">The URL of the webhook that receives POST requests with alert payloads.</param>
public sealed class WebhookAlertSink(Uri endpoint) : IAlertSink
{
    private static readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(5) };

    public async ValueTask SendAsync(SentinelError error, CancellationToken ct)
    {
        var payload = error switch
        {
            SentinelError.ThreatDetected t => new AlertPayload(
                "ThreatDetected",
                t.Result.Severity.ToString(),
                t.Result.DetectorId.ToString(),
                t.Result.Reason,
                t.Action.ToString(),
                t.Session.ToString()),
            SentinelError.PipelineFailure f => new AlertPayload(
                "PipelineFailure", "Unknown", "n/a", f.Message, "n/a", "n/a"),
            _ => new AlertPayload("Unknown", "Unknown", "n/a", string.Empty, "n/a", "n/a")
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
        string Action,
        string Session);
}
