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

    [Fact]
    public async Task GetActiveAssignment_ReadsTheCreatingRequestFromCreatedUsing()
    {
        // Graph names the schedule request that created an activated assignment in createdUsing. A hook
        // process that never saw the request open records the PIM approval under this id.
        var handler = new CapturingHandler(
            _ => Task.CompletedTask,
            """
            {"value":[{"id":"sched-1","status":"Provisioned","createdUsing":"req-pim-123",
              "scheduleInfo":{"startDateTime":"2026-10-17T10:00:00Z",
                "expiration":{"type":"afterDateTime","endDateTime":"2026-10-17T10:15:00Z"}}}]}
            """);
        using var http = new HttpClient(handler);
        using var adapter = new HttpClientRequestAdapter(new AnonymousAuthenticationProvider(), httpClient: http);
        var client = new MicrosoftGraphRoleClient(new GraphServiceClient(adapter));

        var snapshot = await client.GetActiveAssignmentAsync(
            "00000000-0000-0000-0000-000000000001", "00000000-0000-0000-0000-000000000099",
            TestContext.Current.CancellationToken);

        Assert.NotNull(snapshot);
        Assert.Equal("req-pim-123", snapshot!.RequestId);
    }

    [Fact]
    public async Task GetPendingActivationRequest_PicksTheNewestPendingAndFiltersOnSelfActivate()
    {
        HttpRequestMessage? captured = null;
        var handler = new CapturingHandler(
            req => { captured = req; return Task.CompletedTask; },
            """
            {"value":[
              {"id":"old-pending","status":"PendingApproval","createdDateTime":"2026-10-31T09:00:00Z"},
              {"id":"new-pending","status":"PendingApproval","createdDateTime":"2026-10-31T10:00:00Z"},
              {"id":"newer-failed","status":"Failed","createdDateTime":"2026-10-31T11:00:00Z"},
              {"id":"no-time","status":"PendingApproval"}]}
            """);
        using var http = new HttpClient(handler);
        using var adapter = new HttpClientRequestAdapter(new AnonymousAuthenticationProvider(), httpClient: http);
        var client = new MicrosoftGraphRoleClient(new GraphServiceClient(adapter));

        var pending = await client.GetPendingActivationRequestAsync(
            "00000000-0000-0000-0000-000000000001", "00000000-0000-0000-0000-000000000099",
            TestContext.Current.CancellationToken);

        Assert.NotNull(pending);
        Assert.Equal("new-pending", pending!.RequestId);
        Assert.Equal(new DateTimeOffset(2026, 10, 31, 10, 0, 0, TimeSpan.Zero), pending.CreatedAt);
        var query = Uri.UnescapeDataString(captured!.RequestUri!.Query);
        Assert.Contains("action eq 'selfActivate'", query, StringComparison.Ordinal);
    }

    [Fact]
    public async Task GetPendingActivationRequest_FollowsNextLinkToFindAPendingRequestOnLaterPage()
    {
        var calls = 0;
        var handler = new CapturingHandler(
            _ => Task.CompletedTask,
            _ => ++calls == 1
                ? """
                  {"@odata.nextLink":"https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleRequests?$skiptoken=p2",
                   "value":[{"id":"done","status":"Provisioned","createdDateTime":"2026-10-31T08:00:00Z"}]}
                  """
                : """
                  {"value":[{"id":"page2-pending","status":"PendingApproval","createdDateTime":"2026-10-31T09:00:00Z"}]}
                  """);
        using var http = new HttpClient(handler);
        using var adapter = new HttpClientRequestAdapter(new AnonymousAuthenticationProvider(), httpClient: http);
        var client = new MicrosoftGraphRoleClient(new GraphServiceClient(adapter));

        var pending = await client.GetPendingActivationRequestAsync(
            "00000000-0000-0000-0000-000000000001", "00000000-0000-0000-0000-000000000099",
            TestContext.Current.CancellationToken);

        Assert.Equal("page2-pending", pending!.RequestId);
        Assert.Equal(2, calls);
    }

    [Fact]
    public async Task GetPendingActivationRequest_PastThePageCap_ThrowsWithoutFetchingAnotherPage()
    {
        var calls = 0;
        var handler = new CapturingHandler(
            _ => Task.CompletedTask,
            _ =>
            {
                calls++;
                return """
                  {"@odata.nextLink":"https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleRequests?$skiptoken=more",
                   "value":[]}
                  """;
            });
        using var http = new HttpClient(handler);
        using var adapter = new HttpClientRequestAdapter(new AnonymousAuthenticationProvider(), httpClient: http);
        var client = new MicrosoftGraphRoleClient(new GraphServiceClient(adapter));

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await client.GetPendingActivationRequestAsync(
                "00000000-0000-0000-0000-000000000001", "00000000-0000-0000-0000-000000000099",
                TestContext.Current.CancellationToken));

        Assert.Contains("20 pages", ex.Message, StringComparison.Ordinal);
        Assert.Equal(20, calls);
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
        private readonly string _responseJson;

        private readonly Func<HttpRequestMessage, string>? _responder;

        public CapturingHandler(
            Func<HttpRequestMessage, Task> capture,
            string responseJson = "{\"id\":\"req-stub-id\",\"status\":\"PendingApproval\"}")
        {
            _capture = capture;
            _responseJson = responseJson;
        }

        /// <summary>Computes each response body from the request, for multi-page stubs.</summary>
        public CapturingHandler(Func<HttpRequestMessage, Task> capture, Func<HttpRequestMessage, string> responder)
            : this(capture)
        {
            _responder = responder;
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
                    _responder?.Invoke(request) ?? _responseJson,
                    Encoding.UTF8,
                    "application/json"),
            };
        }
    }
}
