using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.Graph;
using Microsoft.Kiota.Abstractions.Authentication;
using Microsoft.Kiota.Http.HttpClientLibrary;
using Xunit;

namespace AI.Sentinel.Approvals.EntraPim.Tests;

/// <summary>
/// Pin the wire-format that <see cref="MicrosoftGraphRoleClient"/> sends to Graph.
/// A Microsoft.Graph or Kiota SDK upgrade that silently drops a property (e.g.
/// renames <c>action</c> or omits the schedule expiration) would otherwise pass
/// our unit tests but break PIM activation in production. Capturing the actual
/// HTTP body and asserting the JSON shape catches that regression early.
/// </summary>
public class MicrosoftGraphRoleClientWireTests
{
    [Fact]
    public async Task CreateActivationRequest_PostsSelfActivateBody()
    {
        var (captured, capturedBody) = await CaptureCreateActivationRequestAsync(
            principalId: "00000000-0000-0000-0000-000000000001",
            roleId: "00000000-0000-0000-0000-000000000099",
            duration: TimeSpan.FromMinutes(15),
            justification: "test");

        Assert.NotNull(captured);
        Assert.Equal(HttpMethod.Post, captured!.Method);
        Assert.Contains(
            "roleAssignmentScheduleRequests",
            captured.RequestUri!.AbsoluteUri,
            StringComparison.Ordinal);

        Assert.NotNull(capturedBody);
        using var doc = JsonDocument.Parse(capturedBody!);
        var root = doc.RootElement;

        // Property names follow Graph's JSON contract (camelCase). selfActivate is the
        // PIM action keyword — without it Graph rejects the request as invalid.
        Assert.Equal("selfActivate", root.GetProperty("action").GetString());
        Assert.Equal(
            "00000000-0000-0000-0000-000000000001",
            root.GetProperty("principalId").GetString());
        Assert.Equal(
            "00000000-0000-0000-0000-000000000099",
            root.GetProperty("roleDefinitionId").GetString());
        Assert.Equal("/", root.GetProperty("directoryScopeId").GetString());
        Assert.Equal("test", root.GetProperty("justification").GetString());

        // ScheduleInfo.Expiration.Duration must be ISO 8601 PT15M for a 15-minute grant.
        // Kiota serialises enum values in camelCase per the OpenAPI generator's default
        // (Microsoft.Graph 5.x) — so ExpirationPatternType.AfterDuration emits as "afterDuration".
        var expiration = root.GetProperty("scheduleInfo").GetProperty("expiration");
        Assert.Equal("afterDuration", expiration.GetProperty("type").GetString());
        Assert.Equal("PT15M", expiration.GetProperty("duration").GetString());
    }

    /// <summary>
    /// Spins up an in-memory Graph SDK pipeline pointed at a capturing HTTP handler,
    /// invokes <see cref="MicrosoftGraphRoleClient.CreateActivationRequestAsync"/>,
    /// and returns the captured outbound request + body.
    /// </summary>
    private static async Task<(HttpRequestMessage? Request, string? Body)>
        CaptureCreateActivationRequestAsync(
            string principalId, string roleId, TimeSpan duration, string justification)
    {
        HttpRequestMessage? captured = null;
        string? capturedBody = null;
        var handler = new CapturingHandler(async req =>
        {
            captured = req;
            if (req.Content is not null)
                capturedBody = await req.Content.ReadAsStringAsync().ConfigureAwait(false);
        });

        using var http = new HttpClient(handler);
        var authProvider = new AnonymousAuthenticationProvider();
        using var adapter = new HttpClientRequestAdapter(authProvider, httpClient: http);
        var graph = new GraphServiceClient(adapter);
        var client = new MicrosoftGraphRoleClient(graph);

        try
        {
            await client.CreateActivationRequestAsync(principalId, roleId, duration, justification, default)
                .ConfigureAwait(false);
        }
        catch (Exception sdkEx) when (sdkEx is not OperationCanceledException)
        {
            // The stub returns a minimal JSON body that may or may not deserialise into
            // a UnifiedRoleAssignmentScheduleRequest depending on Kiota's strictness — we
            // only care about what was SENT, not what came back.
            _ = sdkEx;
        }

        return (captured, capturedBody);
    }

    /// <summary>HttpMessageHandler that records the outbound request and returns a stub response.</summary>
    private sealed class CapturingHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, Task> _capture;

        public CapturingHandler(Func<HttpRequestMessage, Task> capture)
        {
            _capture = capture;
        }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            // Buffer the body so the caller's capture callback can read it; Kiota
            // typically streams content, so reading after dispatch would otherwise fail.
            // LoadIntoBufferAsync(CancellationToken) is .NET 9+ only; net8.0 needs the
            // parameterless overload.
            if (request.Content is not null)
                await request.Content.LoadIntoBufferAsync().ConfigureAwait(false);

            await _capture(request).ConfigureAwait(false);

            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    "{\"id\":\"req-stub-id\",\"status\":\"PendingApproval\"}",
                    Encoding.UTF8,
                    "application/json"),
            };
        }
    }
}
