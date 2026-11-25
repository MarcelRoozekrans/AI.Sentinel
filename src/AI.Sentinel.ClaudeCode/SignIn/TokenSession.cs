namespace AI.Sentinel.ClaudeCode.SignIn;

/// <summary>
/// The tokens the resident process holds (#659). The access token and the refresh token live in memory. The refresh token is also kept
/// in the keychain when there is one, so a restart signs in without the developer; where there is none (headless Linux) it is kept in
/// memory only and the developer signs in again after the process restarts. Nothing here writes a file.
/// </summary>
internal sealed class TokenSession(OidcDeviceClient client, ITokenStore? store, TimeProvider time, Action<string>? log = null)
{
    /// <summary>A token that runs out within this time is renewed before it is used.</summary>
    private static readonly TimeSpan Skew = TimeSpan.FromSeconds(30);

    private const int MaxLoads = 3;

    private readonly SemaphoreSlim _gate = new(1, 1);
    private string? _access;
    private string? _refresh;
    private DateTimeOffset _expiresAt;
    private bool _storeChecked;
    private int _loads;

    public SignInStatus Status
    {
        get
        {
            _gate.Wait();
            try
            {
                LoadFromStore();
                return (_access is not null && time.GetUtcNow() < _expiresAt) || _refresh is not null
                    ? SignInStatus.SignedIn
                    : SignInStatus.SignInNeeded;
            }
            finally
            {
                _gate.Release();
            }
        }
    }

    /// <summary>True when the tokens of a sign-in at this issuer and client are ones this session can refresh.</summary>
    public bool Accepts(string? issuer, string? clientId) => client.IsFor(issuer, clientId);

    /// <summary>Takes the tokens of a sign-in.</summary>
    public void Set(TokenSet tokens)
    {
        ArgumentNullException.ThrowIfNull(tokens);
        _gate.Wait();
        try
        {
            _access = tokens.AccessToken;
            _refresh = tokens.RefreshToken;
            _expiresAt = tokens.ExpiresAt;
            _storeChecked = true;
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>The access token, renewed first when it is about to run out.</summary>
    public async Task<TokenAnswer> GetAccessTokenAsync(CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            // The skew buys an early renewal, so it only applies where there is a refresh token to renew with.
            if (_access is not null && time.GetUtcNow() < (_refresh is null ? _expiresAt : _expiresAt - Skew))
            {
                return new TokenAnswer(TokenAnswerKind.Token, _access);
            }

            LoadFromStore();

            if (_refresh is null)
            {
                // Without a refresh token the access token is used until it expires; then the developer signs in again.
                _access = null;
                return new TokenAnswer(TokenAnswerKind.SignInRequired, null);
            }

            return await RefreshAsync(ct).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    // Called under the gate. After a restart the keychain may hold the refresh token of an earlier sign-in.
    private void LoadFromStore()
    {
        // A keychain that is locked or busy reads as empty, so an empty read is tried again, a few times, before it counts as no token.
        if (!_storeChecked)
        {
            _refresh = store?.Load();
            _storeChecked = store is null || _refresh is not null || ++_loads >= MaxLoads;
        }
    }

    private async Task<TokenAnswer> RefreshAsync(CancellationToken ct)
    {
        try
        {
            var renewed = await client.RefreshAsync(_refresh!, ct).ConfigureAwait(false);
            _access = renewed.AccessToken;
            _expiresAt = renewed.ExpiresAt;
            if (renewed.RefreshToken is not null && !string.Equals(renewed.RefreshToken, _refresh, StringComparison.Ordinal))
            {
                _refresh = renewed.RefreshToken;
                if (store is not null && !store.Save(_refresh))
                {
                    log?.Invoke($"the {store.Name} did not take the new refresh token; it is kept in memory only");
                }
            }

            return new TokenAnswer(TokenAnswerKind.Token, _access);
        }
        catch (SignInException e) when (e.Kind == SignInFailure.Rejected)
        {
            _access = null;
            _refresh = null;
            _ = store?.Delete();
            log?.Invoke("the provider no longer accepts the refresh token: sign-in is needed");
            return new TokenAnswer(TokenAnswerKind.SignInRequired, null);
        }
        catch (SignInException)
        {
            // A provider that is down, or answers against the protocol, does not take the token back: the token is not thrown away for
            // it, and the access token that is still valid, renewed early, is used.
            return _access is not null && time.GetUtcNow() < _expiresAt
                ? new TokenAnswer(TokenAnswerKind.Token, _access)
                : new TokenAnswer(TokenAnswerKind.Unavailable, null);
        }
    }
}
