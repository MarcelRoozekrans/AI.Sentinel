using System.Net;
using System.Text.Json;
using AI.Sentinel.ClaudeCode.SignIn;

namespace AI.Sentinel.ClaudeCode.ServerApprovals;

/// <summary>
/// Calls the approval endpoints of the server (#662). It runs in the resident process, whose <c>HttpClient</c> carries the bearer
/// handler of the sign-in (#659), so the token never leaves that process. Every failure is a status, never an exception: a call
/// that cannot be asked is denied by the caller.
/// </summary>
internal sealed class ApprovalServerClient(HttpClient http, string path = ApprovalServerClient.DefaultPath) : IApprovalChannel
{
    /// <summary>Where the server maps the endpoints unless the host chose another prefix; relative to the server address.</summary>
    public const string DefaultPath = "ai-sentinel/approvals";

    public Task<ApprovalChannelReply> EnsureAsync(ApprovalRequestWire request, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(request);
        var message = new HttpRequestMessage(HttpMethod.Post, path)
        {
            Content = new ByteArrayContent(JsonSerializer.SerializeToUtf8Bytes(request, ApprovalWireJsonContext.Default.ApprovalRequestWire)),
        };
        message.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");
        return SendAsync(message, ct);
    }

    public Task<ApprovalChannelReply> GetAsync(string requestId, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrEmpty(requestId);
        return SendAsync(new HttpRequestMessage(HttpMethod.Get, $"{path}/{Uri.EscapeDataString(requestId)}"), ct);
    }

    private async Task<ApprovalChannelReply> SendAsync(HttpRequestMessage message, CancellationToken ct)
    {
        using var _ = message;
        try
        {
            using var response = await http.SendAsync(message, ct).ConfigureAwait(false);
            return await ReplyAsync(response, ct).ConfigureAwait(false);
        }
        catch (SignInRequiredException)
        {
            return new ApprovalChannelReply(ApprovalChannelStatus.SignInNeeded);
        }
        catch (Exception e) when (e is HttpRequestException or OperationCanceledException or IOException or JsonException or InvalidOperationException)
        {
            // A server that is down, slow or answers nonsense is no answer: the call is denied as unreachable.
            return new ApprovalChannelReply(ApprovalChannelStatus.Unreachable);
        }
    }

    private static async Task<ApprovalChannelReply> ReplyAsync(HttpResponseMessage response, CancellationToken ct)
    {
        switch (response.StatusCode)
        {
            case HttpStatusCode.OK or HttpStatusCode.Created:
                return await ReadStateAsync(response, ct).ConfigureAwait(false);
            case HttpStatusCode.Unauthorized:
                return new ApprovalChannelReply(ApprovalChannelStatus.SignInNeeded);
            case HttpStatusCode.Forbidden:
                return new ApprovalChannelReply(ApprovalChannelStatus.Refused);
            case HttpStatusCode.NotFound:
                return new ApprovalChannelReply(ApprovalChannelStatus.NotFound);
            default:
                // 5xx, 429, 503 before a configuration is published, and anything else: the server cannot answer now.
                return new ApprovalChannelReply(ApprovalChannelStatus.Unreachable);
        }
    }

    private static async Task<ApprovalChannelReply> ReadStateAsync(HttpResponseMessage response, CancellationToken ct)
    {
        var stream = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        await using var _ = stream.ConfigureAwait(false);
        var state = await JsonSerializer.DeserializeAsync(stream, ApprovalWireJsonContext.Default.ApprovalStateWire, ct).ConfigureAwait(false);
        return state is null ? new ApprovalChannelReply(ApprovalChannelStatus.Unreachable) : new ApprovalChannelReply(ApprovalChannelStatus.Ok, state);
    }
}
