using System.Net;
using System.Text;
using System.Text.Json;

namespace AI.Sentinel.Tests.ClaudeCode.SignIn;

/// <summary>An OIDC provider and a Sentinel server in one in-process handler: discovery, the device authorization endpoint, the token
/// endpoint with its polling answers and refresh, and the endpoint that hands out the server's public keys. No socket is opened.</summary>
internal sealed class FakeOidcServer : HttpMessageHandler
{
    public const string Issuer = "https://idp.example.com";
    public const string Server = "https://sentinel.example.com";
    public const string ClientId = "sentinel-cli";

    private int _polls;
    private int _issued;

    /// <summary>Answers before the token endpoint gives a token: each entry is an OAuth error code.</summary>
    public List<string> PollErrors { get; } = [];

    public bool IssueRefreshToken { get; set; } = true;

    public int? AccessLifetimeSeconds { get; set; } = 3600;

    public int DeviceLifetimeSeconds { get; set; } = 600;

    public int Interval { get; set; } = 5;

    /// <summary>The refresh token the provider accepts; a refresh with another one answers invalid_grant.</summary>
    public string? ValidRefreshToken { get; set; }

    /// <summary>The first this many polls time out, as an HttpClient timeout does: a TaskCanceledException that is not a cancellation.</summary>
    public int PollTimeouts { get; set; }

    /// <summary>When set, a refresh answers this OAuth error (400).</summary>
    public string? RefreshError { get; set; }

    /// <summary>When true the token endpoint is down for a refresh (503).</summary>
    public bool RefreshUnavailable { get; set; }

    /// <summary>The issuer the discovery document names; the real one when null.</summary>
    public string? DiscoveryIssuer { get; set; }

    /// <summary>When set, a refresh answers this status with this body, whatever the refresh token is.</summary>
    public (HttpStatusCode Status, string Body)? RefreshRaw { get; set; }

    /// <summary>What the token endpoint puts in access_token; the issued one when null.</summary>
    public string? AccessTokenField { get; set; }

    /// <summary>Awaited before a refresh is answered, so a test can hold a refresh in flight.</summary>
    public Func<Task>? BeforeRefresh { get; set; }

    /// <summary>What the token endpoint puts in refresh_token; the issued one when null.</summary>
    public string? RefreshTokenField { get; set; }

    public string Organisation { get; set; } = "acme";

    public List<string> ServerKeys { get; set; } = [];

    public string? DeviceEndpoint { get; set; }

    public List<string> Requests { get; } = [];

    public List<string?> Authorizations { get; } = [];

    public List<string> Bodies { get; } = [];

    public int PollCount => _polls;

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var path = request.RequestUri!.AbsoluteUri;
        Requests.Add(request.Method + " " + path);
        Authorizations.Add(request.Headers.Authorization?.ToString());
        var body = request.Content is null ? string.Empty : await request.Content.ReadAsStringAsync(cancellationToken);
        Bodies.Add(body);

        if (string.Equals(path, Issuer + "/.well-known/openid-configuration", StringComparison.Ordinal))
        {
            return Json(HttpStatusCode.OK, new
            {
                issuer = DiscoveryIssuer ?? Issuer,
                device_authorization_endpoint = DeviceEndpoint ?? Issuer + "/device",
                token_endpoint = Issuer + "/token",
            });
        }

        if (string.Equals(path, Issuer + "/device", StringComparison.Ordinal))
        {
            return Json(HttpStatusCode.OK, new
            {
                device_code = "dc-1",
                user_code = "WDJB-MJHT",
                verification_uri = Issuer + "/activate",
                verification_uri_complete = Issuer + "/activate?user_code=WDJB-MJHT",
                expires_in = DeviceLifetimeSeconds,
                interval = Interval,
            });
        }

        if (string.Equals(path, Issuer + "/token", StringComparison.Ordinal))
        {
            var form = ParseForm(body);
            var grant = form.GetValueOrDefault("grant_type");
            if (string.Equals(grant, "urn:ietf:params:oauth:grant-type:device_code", StringComparison.Ordinal))
            {
                return Poll(form);
            }

            return string.Equals(grant, "refresh_token", StringComparison.Ordinal)
                ? await RefreshAsync(form)
                : Json(HttpStatusCode.BadRequest, new { error = "unsupported_grant_type" });
        }

        if (string.Equals(path, Server + "/.well-known/ai-sentinel/profile-keys", StringComparison.Ordinal))
        {
            return request.Headers.Authorization?.Scheme is "Bearer"
                ? Json(HttpStatusCode.OK, new { organisation = Organisation, keys = ServerKeys })
                : new HttpResponseMessage(HttpStatusCode.Unauthorized);
        }

        if (path.StartsWith(Server + "/echo", StringComparison.Ordinal))
        {
            return new HttpResponseMessage(HttpStatusCode.NoContent);
        }

        return new HttpResponseMessage(HttpStatusCode.NotFound);
    }

    private HttpResponseMessage Poll(Dictionary<string, string> form)
    {
        if (!string.Equals(form.GetValueOrDefault("device_code"), "dc-1", StringComparison.Ordinal) || !string.Equals(form.GetValueOrDefault("client_id"), ClientId, StringComparison.Ordinal))
        {
            return Json(HttpStatusCode.BadRequest, new { error = "invalid_grant" });
        }

        var index = _polls++;
        if (index < PollTimeouts)
        {
            throw new TaskCanceledException("timed out", new TimeoutException());
        }

        index -= PollTimeouts;
        if (index < PollErrors.Count)
        {
            return Json(HttpStatusCode.BadRequest, new { error = PollErrors[index] });
        }

        return Tokens();
    }

    private async Task<HttpResponseMessage> RefreshAsync(Dictionary<string, string> form)
    {
        if (BeforeRefresh is { } wait)
        {
            await wait();
        }

        return Refresh(form);
    }

    private HttpResponseMessage Refresh(Dictionary<string, string> form)
    {
        if (RefreshRaw is { } raw)
        {
            return new HttpResponseMessage(raw.Status) { Content = new StringContent(raw.Body, Encoding.UTF8, "application/json") };
        }

        if (RefreshUnavailable)
        {
            return new HttpResponseMessage(HttpStatusCode.ServiceUnavailable);
        }

        if (RefreshError is not null)
        {
            return Json(HttpStatusCode.BadRequest, new { error = RefreshError });
        }

        if (ValidRefreshToken is null || !string.Equals(form.GetValueOrDefault("refresh_token"), ValidRefreshToken, StringComparison.Ordinal))
        {
            return Json(HttpStatusCode.BadRequest, new { error = "invalid_grant" });
        }

        return Tokens();
    }

    private HttpResponseMessage Tokens()
    {
        var n = ++_issued;
        var refresh = IssueRefreshToken ? "rt-" + n : null;
        ValidRefreshToken = refresh;
        refresh = RefreshTokenField ?? refresh;
        return Json(HttpStatusCode.OK, new
        {
            access_token = AccessTokenField ?? "at-" + n,
            token_type = "Bearer",
            expires_in = AccessLifetimeSeconds,
            refresh_token = refresh,
        });
    }

    private static HttpResponseMessage Json(HttpStatusCode status, object value) =>
        new(status) { Content = new StringContent(JsonSerializer.Serialize(value), Encoding.UTF8, "application/json") };

    private static Dictionary<string, string> ParseForm(string body)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var pair in body.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var parts = pair.Split('=', 2);
            result[Uri.UnescapeDataString(parts[0])] = parts.Length > 1 ? Uri.UnescapeDataString(parts[1].Replace('+', ' ')) : string.Empty;
        }

        return result;
    }
}
