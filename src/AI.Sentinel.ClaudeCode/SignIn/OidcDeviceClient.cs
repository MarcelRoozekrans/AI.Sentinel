using System.Text.Json;

namespace AI.Sentinel.ClaudeCode.SignIn;

/// <summary>
/// The OIDC device authorization grant (RFC 8628) and the refresh grant, against any provider that publishes a discovery document.
/// Every endpoint must be https, or http on loopback. A token is never put in an exception message.
/// </summary>
internal sealed class OidcDeviceClient(HttpClient http, SignInSettings settings, TimeProvider time, Func<TimeSpan, CancellationToken, Task>? delay = null)
{
    private static readonly TimeSpan SlowDownStep = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan DefaultInterval = TimeSpan.FromSeconds(5);

    private readonly Func<TimeSpan, CancellationToken, Task> _delay = delay ?? ((by, ct) => Task.Delay(by, time, ct));
    private Uri? _deviceEndpoint;
    private Uri? _tokenEndpoint;

    /// <summary>Asks the provider for a device code.</summary>
    public async Task<DeviceAuthorization> StartAsync(CancellationToken ct)
    {
        await DiscoverAsync(ct).ConfigureAwait(false);
        using var content = Form(("client_id", settings.ClientId), ("scope", settings.Scope));
        var wire = await PostAsync(_deviceEndpoint!, content, SignInJsonContext.Default.DeviceAuthorizationWire, ct).ConfigureAwait(false);
        if (string.IsNullOrEmpty(wire.DeviceCode) || string.IsNullOrEmpty(wire.UserCode) || wire.ExpiresIn <= 0
            || !Uri.TryCreate(wire.VerificationUri, UriKind.Absolute, out var verification) || !SignInSettings.IsSecure(verification))
        {
            throw new SignInException(SignInFailure.Protocol, "the device authorization answer is incomplete");
        }

        Uri? complete = null;
        if (wire.VerificationUriComplete is not null
            && (!Uri.TryCreate(wire.VerificationUriComplete, UriKind.Absolute, out complete) || !SignInSettings.IsSecure(complete)))
        {
            complete = null;
        }

        return new DeviceAuthorization(
            wire.DeviceCode, wire.UserCode, verification, complete,
            time.GetUtcNow().AddSeconds(wire.ExpiresIn),
            wire.Interval is > 0 ? TimeSpan.FromSeconds(wire.Interval.Value) : DefaultInterval);
    }

    /// <summary>Polls the token endpoint until the developer approves, the code expires or the provider refuses.</summary>
    public async Task<TokenSet> PollAsync(DeviceAuthorization authorization, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(authorization);
        await DiscoverAsync(ct).ConfigureAwait(false);
        var interval = authorization.Interval;
        while (true)
        {
            await _delay(interval, ct).ConfigureAwait(false);
            if (time.GetUtcNow() >= authorization.ExpiresAt)
            {
                throw new SignInException(SignInFailure.Expired, "the device code expired before it was approved");
            }

            using var content = Form(
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("device_code", authorization.DeviceCode),
                ("client_id", settings.ClientId));
            var (wire, status) = await TokenAsync(content, ct).ConfigureAwait(false);
            switch (wire.Error)
            {
                case null when wire.AccessToken is not null:
                    return ToTokens(wire, previousRefreshToken: null);
                case "authorization_pending":
                    continue;
                case "slow_down":
                    interval += SlowDownStep;
                    continue;
                case "expired_token":
                    throw new SignInException(SignInFailure.Expired, "the device code expired before it was approved");
                case "access_denied":
                    throw new SignInException(SignInFailure.Denied, "the sign-in was refused");
                default:
                    throw new SignInException(SignInFailure.Protocol, $"the provider answered {(int)status} with error '{SafeError(wire.Error)}'");
            }
        }
    }

    /// <summary>Gets a new access token with a refresh token. A provider that does not rotate keeps the old refresh token.</summary>
    /// <exception cref="SignInException"><see cref="SignInFailure.Rejected"/> when the provider refuses the refresh token, and
    /// <see cref="SignInFailure.Unavailable"/> when it cannot be reached.</exception>
    public async Task<TokenSet> RefreshAsync(string refreshToken, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrEmpty(refreshToken);
        await DiscoverAsync(ct).ConfigureAwait(false);
        using var content = Form(("grant_type", "refresh_token"), ("refresh_token", refreshToken), ("client_id", settings.ClientId), ("scope", settings.Scope));
        var (wire, status) = await TokenAsync(content, ct).ConfigureAwait(false);
        if (wire.Error is not null)
        {
            throw wire.Error is "invalid_grant" or "invalid_token" or "unauthorized_client"
                ? new SignInException(SignInFailure.Rejected, "the provider no longer accepts the refresh token")
                : new SignInException(SignInFailure.Unavailable, $"the provider answered {(int)status} with error '{SafeError(wire.Error)}'");
        }

        return wire.AccessToken is null
            ? throw new SignInException(SignInFailure.Protocol, "the token answer holds no access token")
            : ToTokens(wire, refreshToken);
    }

    private TokenSet ToTokens(TokenResponseWire wire, string? previousRefreshToken)
    {
        if (!string.Equals(wire.TokenType, "Bearer", StringComparison.OrdinalIgnoreCase))
        {
            throw new SignInException(SignInFailure.Protocol, "the provider issued a token that is not a bearer token");
        }

        var lifetime = wire.ExpiresIn is > 0 ? wire.ExpiresIn.Value : 3600;
        return new TokenSet(wire.AccessToken!, wire.RefreshToken ?? previousRefreshToken, time.GetUtcNow().AddSeconds(lifetime));
    }

    private async Task DiscoverAsync(CancellationToken ct)
    {
        if (_tokenEndpoint is not null)
        {
            return;
        }

        var address = new Uri(settings.Issuer.AbsoluteUri.TrimEnd('/') + "/.well-known/openid-configuration");
        var document = await GetAsync(address, SignInJsonContext.Default.OidcDiscovery, ct).ConfigureAwait(false);
        if (!Uri.TryCreate(document.DeviceAuthorizationEndpoint, UriKind.Absolute, out var device) || !SignInSettings.IsSecure(device)
            || !Uri.TryCreate(document.TokenEndpoint, UriKind.Absolute, out var token) || !SignInSettings.IsSecure(token))
        {
            throw new SignInException(SignInFailure.Protocol, "the provider offers no secure device authorization grant");
        }

        _deviceEndpoint = device;
        _tokenEndpoint = token;
    }

    private async Task<(TokenResponseWire Wire, System.Net.HttpStatusCode Status)> TokenAsync(HttpContent content, CancellationToken ct)
    {
        try
        {
            using var response = await http.PostAsync(_tokenEndpoint, content, ct).ConfigureAwait(false);
            var text = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            if (!string.IsNullOrWhiteSpace(text) && Parse(text) is { } wire)
            {
                return (wire, response.StatusCode);
            }

            // An error without a body: a gateway or a provider that is down.
            throw new SignInException(SignInFailure.Unavailable, $"the provider answered {(int)response.StatusCode}");
        }
        catch (HttpRequestException e)
        {
            throw new SignInException(SignInFailure.Unavailable, $"the provider cannot be reached ({e.GetType().Name})");
        }
    }

    private static TokenResponseWire? Parse(string text)
    {
        try
        {
            return JsonSerializer.Deserialize(text, SignInJsonContext.Default.TokenResponseWire);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private async Task<T> GetAsync<T>(Uri address, System.Text.Json.Serialization.Metadata.JsonTypeInfo<T> info, CancellationToken ct)
        where T : class
    {
        try
        {
            using var response = await http.GetAsync(address, ct).ConfigureAwait(false);
            return await ReadAsync(response, info, ct).ConfigureAwait(false);
        }
        catch (HttpRequestException e)
        {
            throw new SignInException(SignInFailure.Unavailable, $"{address.Host} cannot be reached ({e.GetType().Name})");
        }
    }

    private async Task<T> PostAsync<T>(Uri address, HttpContent content, System.Text.Json.Serialization.Metadata.JsonTypeInfo<T> info, CancellationToken ct)
        where T : class
    {
        try
        {
            using var response = await http.PostAsync(address, content, ct).ConfigureAwait(false);
            return await ReadAsync(response, info, ct).ConfigureAwait(false);
        }
        catch (HttpRequestException e)
        {
            throw new SignInException(SignInFailure.Unavailable, $"{address.Host} cannot be reached ({e.GetType().Name})");
        }
    }

    private static async Task<T> ReadAsync<T>(HttpResponseMessage response, System.Text.Json.Serialization.Metadata.JsonTypeInfo<T> info, CancellationToken ct)
        where T : class
    {
        if (!response.IsSuccessStatusCode)
        {
            throw new SignInException(SignInFailure.Unavailable, $"{response.RequestMessage?.RequestUri?.Host} answered {(int)response.StatusCode}");
        }

        try
        {
            var text = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            return JsonSerializer.Deserialize(text, info) ?? throw new SignInException(SignInFailure.Protocol, "the answer is empty");
        }
        catch (JsonException)
        {
            throw new SignInException(SignInFailure.Protocol, "the answer is not JSON");
        }
    }

    private static FormUrlEncodedContent Form(params (string Key, string Value)[] fields) =>
        new(fields.Select(f => new KeyValuePair<string, string>(f.Key, f.Value)));

    // An error code is a short token of the OAuth registry; anything else is not echoed.
    private static string SafeError(string? error) =>
        error is { Length: <= 40 } && error.All(c => char.IsAsciiLetterOrDigit(c) || c == '_') ? error : "unknown";
}
