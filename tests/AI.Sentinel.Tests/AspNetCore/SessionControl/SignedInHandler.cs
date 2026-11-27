namespace AI.Sentinel.Tests.AspNetCore.SessionControl;

/// <summary>Adds the headers of one signed-in developer to every request, as the bearer token handler adds a token.</summary>
internal sealed class SignedInHandler(HttpMessageHandler inner, string user = "dave", string groups = "") : DelegatingHandler(inner)
{
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        SessionControlTestHost.Sign(request, user, groups);
        return base.SendAsync(request, cancellationToken);
    }
}
