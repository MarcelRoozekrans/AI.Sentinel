using AI.Sentinel.ClaudeCode.Resident;
using AI.Sentinel.ClaudeCode.SignIn;
using AI.Sentinel.Profiles;
using AI.Sentinel.Tests.ClaudeCode.Resident;
using Xunit;

namespace AI.Sentinel.Tests.ClaudeCode.SignIn;

/// <summary>Using the tokens: the resident process holds them, refreshes them and sends them on every server request.</summary>
public partial class DeviceCodeSignInTests
{
    private async Task<TokenSession> SignedIn(ITokenStore? store = null)
    {
        _server.ServerKeys.Add(Convert.ToBase64String(ProfileSigningKey.Generate().PublicKey));
        var outcome = await SignIn().RunAsync(_ => { }, TestContext.Current.CancellationToken);
        var session = new TokenSession(Client(), store, _time);
        session.Set(outcome.Tokens);
        return session;
    }

    [Fact]
    public async Task The_access_token_is_refreshed_without_a_new_sign_in()
    {
        var session = await SignedIn();
        var first = await session.GetAccessTokenAsync(TestContext.Current.CancellationToken);
        Assert.Equal(TokenAnswerKind.Token, first.Kind);
        Assert.Equal("at-1", first.AccessToken);

        _time.Advance(TimeSpan.FromSeconds(3600));
        var second = await session.GetAccessTokenAsync(TestContext.Current.CancellationToken);
        Assert.Equal("at-2", second.AccessToken);
        Assert.Equal(SignInStatus.SignedIn, session.Status);
    }

    [Fact]
    public async Task A_rejected_refresh_token_reports_that_sign_in_is_needed()
    {
        var session = await SignedIn();
        _server.ValidRefreshToken = "someone-else";
        _time.Advance(TimeSpan.FromSeconds(3600));

        var answer = await session.GetAccessTokenAsync(TestContext.Current.CancellationToken);

        Assert.Equal(TokenAnswerKind.SignInRequired, answer.Kind);
        Assert.Equal(SignInStatus.SignInNeeded, session.Status);
        Assert.Equal(TokenAnswerKind.SignInRequired, (await session.GetAccessTokenAsync(TestContext.Current.CancellationToken)).Kind);
    }

    [Fact]
    public async Task A_provider_that_is_down_is_not_a_reason_to_sign_in_again()
    {
        var session = await SignedIn();
        _server.RefreshUnavailable = true;
        _time.Advance(TimeSpan.FromSeconds(3600));

        var answer = await session.GetAccessTokenAsync(TestContext.Current.CancellationToken);
        Assert.Equal(TokenAnswerKind.Unavailable, answer.Kind);
        Assert.Equal(SignInStatus.SignedIn, session.Status);

        _server.RefreshUnavailable = false;
        Assert.Equal("at-2", (await session.GetAccessTokenAsync(TestContext.Current.CancellationToken)).AccessToken);
    }

    [Fact]
    public async Task A_provider_without_refresh_tokens_signs_in_and_then_reports_sign_in_needed_at_expiry()
    {
        _server.IssueRefreshToken = false;
        var session = await SignedIn();

        Assert.Equal("at-1", (await session.GetAccessTokenAsync(TestContext.Current.CancellationToken)).AccessToken);
        _time.Advance(TimeSpan.FromSeconds(3600));
        Assert.Equal(TokenAnswerKind.SignInRequired, (await session.GetAccessTokenAsync(TestContext.Current.CancellationToken)).Kind);
        Assert.Equal(SignInStatus.SignInNeeded, session.Status);
    }

    [Fact]
    public async Task Every_server_request_carries_the_access_token_and_a_missing_sign_in_is_reported()
    {
        var session = await SignedIn();
        using var http = new HttpClient(new BearerTokenHandler(session, _server));
        using var response = await http.GetAsync(new Uri(FakeOidcServer.Server + "/echo"), TestContext.Current.CancellationToken);
        Assert.Equal(System.Net.HttpStatusCode.NoContent, response.StatusCode);
        Assert.Equal("Bearer at-1", _server.Authorizations[^1]);

        var signedOut = new TokenSession(Client(), null, _time);
        using var plain = new HttpClient(new BearerTokenHandler(signedOut, _server));
        await Assert.ThrowsAsync<SignInRequiredException>(() => plain.GetAsync(new Uri(FakeOidcServer.Server + "/echo"), TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task The_resident_process_takes_the_tokens_over_the_local_channel()
    {
        var session = new TokenSession(Client(), null, _time);
        await using var host = new HostedResident(_dir, tokens: session);
        await host.WaitUntilListeningAsync();
        var client = new ResidentClient(host.Settings);

        var before = await client.SendAsync(new ResidentRequest { Op = ResidentOps.SignInStatus }, TimeSpan.FromSeconds(5));
        Assert.Equal("sign_in_needed", before!.SignIn);

        var tokens = new TokenSet("at-9", "rt-9", _time.GetUtcNow().AddHours(1));
        var set = await client.SendAsync(new ResidentRequest { Op = ResidentOps.SignIn, Tokens = tokens }, TimeSpan.FromSeconds(5));
        Assert.True(set!.Ok);

        var after = await client.SendAsync(new ResidentRequest { Op = ResidentOps.SignInStatus }, TimeSpan.FromSeconds(5));
        Assert.Equal("signed_in", after!.SignIn);
        Assert.Equal("at-9", (await session.GetAccessTokenAsync(TestContext.Current.CancellationToken)).AccessToken);
    }

    [Fact]
    public async Task A_resident_process_without_sign_in_settings_refuses_the_operation()
    {
        await using var host = new HostedResident(_dir);
        await host.WaitUntilListeningAsync();
        var client = new ResidentClient(host.Settings);
        var response = await client.SendAsync(new ResidentRequest { Op = ResidentOps.SignInStatus }, TimeSpan.FromSeconds(5));
        Assert.False(response!.Ok);
        Assert.Equal("off", response.SignIn);
    }
}
