using System.Net.Http.Headers;

namespace AI.Sentinel.ClaudeCode.SignIn;

/// <summary>Puts the access token on every request to the server. The token goes to the server's address only: the handler is built
/// for one <c>HttpClient</c> of the server, and a request to another host is refused, as is a request with no address.</summary>
internal sealed class BearerTokenHandler(TokenSession session, HttpMessageHandler inner, Uri server) : DelegatingHandler(inner)
{
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(server);
        if (request.RequestUri is not { } to || !string.Equals(to.Authority, server.Authority, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("a token is sent to the server only");
        }

        var answer = await session.GetAccessTokenAsync(cancellationToken).ConfigureAwait(false);
        switch (answer.Kind)
        {
            case TokenAnswerKind.Token:
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", answer.AccessToken);
                return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
            case TokenAnswerKind.SignInRequired:
                throw new SignInRequiredException();
            default:
                throw new HttpRequestException("the identity provider cannot be reached to renew the token");
        }
    }
}
