using System.Net;
using System.Text.Json;

namespace AI.Sentinel.Tests.ClaudeCode.Events;

/// <summary>A server that takes batches, can be switched off, and keeps what it received.</summary>
internal sealed class EventServerStub : HttpMessageHandler
{
    private readonly List<JsonElement> _batches = [];
    private readonly List<JsonElement> _requests = [];

    public bool Down { get; set; }

    public HttpStatusCode Status { get; set; } = HttpStatusCode.OK;

    public IReadOnlyList<JsonElement> Batches => _batches;

    /// <summary>Every request body, also the ones the server refused.</summary>
    public IReadOnlyList<JsonElement> Requests => _requests;

    /// <summary>Runs after a batch was taken, before the answer goes back.</summary>
    public Action? AfterTaken { get; set; }

    public IEnumerable<JsonElement> Events => _batches.SelectMany(b => b.GetProperty("events").EnumerateArray());

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (Down)
        {
            throw new HttpRequestException("the server is down");
        }

        var body = await request.Content!.ReadAsStringAsync(cancellationToken);
        _requests.Add(JsonDocument.Parse(body).RootElement.Clone());
        if ((int)Status < 300)
        {
            _batches.Add(JsonDocument.Parse(body).RootElement.Clone());
            AfterTaken?.Invoke();
        }

        return new HttpResponseMessage(Status);
    }
}
