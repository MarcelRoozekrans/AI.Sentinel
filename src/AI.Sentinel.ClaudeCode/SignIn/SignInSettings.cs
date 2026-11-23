namespace AI.Sentinel.ClaudeCode.SignIn;

/// <summary>
/// The settings of the sign-in (#659): the server and the OIDC client. All are optional and off by default: with none of them set
/// nothing signs in, no token is held and no request is authorised, as before.
/// </summary>
/// <param name="ServerUrl">The Sentinel server.</param>
/// <param name="Issuer">The identity provider; its discovery document names the device authorization and the token endpoint.</param>
/// <param name="ClientId">The public client of the plugin at the provider.</param>
/// <param name="Scope">The scopes asked for; <c>offline_access</c> asks for a refresh token.</param>
internal sealed record SignInSettings(Uri ServerUrl, Uri Issuer, string ClientId, string Scope)
{
    public const string ServerVariable = "SENTINEL_HOOK_SERVER_URL";
    public const string IssuerVariable = "SENTINEL_HOOK_OIDC_ISSUER";
    public const string ClientIdVariable = "SENTINEL_HOOK_OIDC_CLIENT_ID";
    public const string ScopeVariable = "SENTINEL_HOOK_OIDC_SCOPE";

    public const string DefaultScope = "openid offline_access";

    /// <summary>The settings, or <see langword="null"/> when none are set (<paramref name="problem"/> is then null too) or the set
    /// ones cannot be used (<paramref name="problem"/> says why).</summary>
    public static SignInSettings? FromEnvironment(IReadOnlyDictionary<string, string?> env, out string? problem)
    {
        ArgumentNullException.ThrowIfNull(env);
        problem = null;
        var server = Value(env, ServerVariable);
        var issuer = Value(env, IssuerVariable);
        var clientId = Value(env, ClientIdVariable);
        if (server is null && issuer is null && clientId is null)
        {
            return null;
        }

        foreach (var (name, value) in new[] { (ServerVariable, server), (IssuerVariable, issuer), (ClientIdVariable, clientId) })
        {
            if (value is null)
            {
                problem = $"sign-in needs {ServerVariable}, {IssuerVariable} and {ClientIdVariable}; {name} is not set";
                return null;
            }
        }

        if (!TryUri(server!, ServerVariable, out var serverUrl, out problem) || !TryUri(issuer!, IssuerVariable, out var issuerUrl, out problem))
        {
            return null;
        }

        return new SignInSettings(serverUrl!, issuerUrl!, clientId!, Value(env, ScopeVariable) ?? DefaultScope);
    }

    /// <summary>True for an https address, or for http on the loopback interface, where a test server or a local provider runs.</summary>
    internal static bool IsSecure(Uri uri) =>
        uri.IsAbsoluteUri && (string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal) || (string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.Ordinal) && uri.IsLoopback));

    private static bool TryUri(string text, string name, out Uri? uri, out string? problem)
    {
        problem = null;
        if (!Uri.TryCreate(text, UriKind.Absolute, out uri) || !IsSecure(uri))
        {
            problem = $"{name} must be an https address";
            uri = null;
            return false;
        }

        return true;
    }

    private static string? Value(IReadOnlyDictionary<string, string?> env, string name) =>
        env.TryGetValue(name, out var v) && !string.IsNullOrWhiteSpace(v) ? v.Trim() : null;
}
