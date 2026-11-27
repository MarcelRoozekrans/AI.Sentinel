using System.Net;
using System.Text.Json;

namespace AI.Sentinel.Tests.ClaudeCode.Events;

/// <summary>A server that takes batches, can be switched off, and keeps what it received.</summary>
internal sealed class EventServerStub : HttpMessageHandler
{
    private readonly List<JsonElement> _batches = [];

    public bool Down { get; set; }

    public HttpStatusCode Status { get; set; } = HttpStatusCode.OK;

    public IReadOnlyList<JsonElement> Batches => _batches;

    public IEnumerable<JsonElement> Events => _batches.SelectMany(b => b.GetProperty("events").EnumerateArray());

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (Down)
        {
            throw new HttpRequestException("the server is down");
        }

        var body = await request.Content!.ReadAsStringAsync(cancellationToken);
        if ((int)Status < 300)
        {
            _batches.Add(JsonDocument.Parse(body).RootElement.Clone());
        }

        return new HttpResponseMessage(Status);
    }
}
