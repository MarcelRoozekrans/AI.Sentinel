using System.Net.Http.Headers;
using System.Text.Json;
using AI.Sentinel.Profiles;

namespace AI.Sentinel.ClaudeCode.SignIn;

/// <summary>
/// The sign-in itself: a device code from the identity provider, then the server's public keys, pinned with that sign-in.
/// The client contract for the keys is <c>GET {server}/.well-known/ai-sentinel/profile-keys</c> with the access token as a bearer
/// token, answering <c>{"organisation": "...", "keys": ["base64 of an Ed25519 public key", ...]}</c>. The server side is #664.
/// </summary>
internal sealed class DeviceCodeSignIn(OidcDeviceClient client, HttpClient http, SignInSettings settings)
{
    /// <summary>The path of the server's endpoint that hands out the keys.</summary>
    public const string KeysPath = "/.well-known/ai-sentinel/profile-keys";

    /// <param name="show">Shows the developer where to go and which code to type.</param>
    /// <param name="ct">Cancels the sign-in.</param>
    public async Task<SignInOutcome> RunAsync(Action<DeviceAuthorization> show, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(show);
        var authorization = await client.StartAsync(ct).ConfigureAwait(false);
        show(authorization);
        var tokens = await client.PollAsync(authorization, ct).ConfigureAwait(false);
        var (organisation, keys) = await FetchKeysAsync(tokens.AccessToken, ct).ConfigureAwait(false);
        return new SignInOutcome(tokens, organisation, keys);
    }

    private async Task<(string Organisation, PinnedProfileKeys Keys)> FetchKeysAsync(string accessToken, CancellationToken ct)
    {
        var address = new Uri(settings.ServerUrl.AbsoluteUri.TrimEnd('/') + KeysPath);
        using var request = new HttpRequestMessage(HttpMethod.Get, address);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        ProfileKeysWire? wire;
        try
        {
            using var response = await http.SendAsync(request, ct).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                throw new SignInException(SignInFailure.Unavailable, $"the server answered {(int)response.StatusCode} to the request for its keys");
            }

            var text = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            wire = JsonSerializer.Deserialize(text, SignInJsonContext.Default.ProfileKeysWire);
        }
        catch (HttpRequestException e)
        {
            throw new SignInException(SignInFailure.Unavailable, $"the server cannot be reached ({e.GetType().Name})");
        }
        catch (JsonException)
        {
            throw new SignInException(SignInFailure.Protocol, "the server's key list is not JSON");
        }

        if (string.IsNullOrWhiteSpace(wire?.Organisation) || wire.Keys is not { Count: > 0 })
        {
            throw new SignInException(SignInFailure.Protocol, "the server names no organisation or no keys");
        }

        try
        {
            return (wire.Organisation, PinnedProfileKeys.FromBase64(wire.Keys));
        }
        catch (Exception e) when (e is FormatException or ArgumentException)
        {
            throw new SignInException(SignInFailure.Protocol, "the server's key list holds a key that is not an Ed25519 public key");
        }
    }
}
