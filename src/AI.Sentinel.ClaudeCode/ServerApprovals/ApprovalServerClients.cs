using AI.Sentinel.ClaudeCode.SignIn;

namespace AI.Sentinel.ClaudeCode.ServerApprovals;

/// <summary>Builds the <c>HttpClient</c> of the resident process for the server: the bearer handler of the sign-in puts the access
/// token on requests to the server's address only (#659).</summary>
internal static class ApprovalServerClients
{
    /// <summary>The longest one call to the server takes; the hook waits a little longer, see <see cref="ResidentApprovalChannel.DefaultBudget"/>.</summary>
    public static readonly TimeSpan CallTimeout = TimeSpan.FromSeconds(4);

    public static HttpClient NewHttpClient(TokenSession tokens, Uri server)
    {
        ArgumentNullException.ThrowIfNull(tokens);
        ArgumentNullException.ThrowIfNull(server);
        // A base address that ends in a slash keeps a path of the server, such as a reverse proxy prefix, when a relative path is added.
        var baseAddress = server.AbsoluteUri.EndsWith('/') ? server : new Uri(server.AbsoluteUri + "/");
        return new HttpClient(new BearerTokenHandler(tokens, new SocketsHttpHandler { AllowAutoRedirect = false }, server)) { BaseAddress = baseAddress, Timeout = CallTimeout };
    }
}
